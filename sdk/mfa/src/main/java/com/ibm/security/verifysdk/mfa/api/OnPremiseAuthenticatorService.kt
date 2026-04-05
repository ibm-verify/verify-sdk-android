/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import android.net.Uri
import com.ibm.security.verifysdk.authentication.api.OAuthProvider
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.extension.entering
import com.ibm.security.verifysdk.core.extension.exiting
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.mfa.MFAAttributeInfo
import com.ibm.security.verifysdk.mfa.MFAServiceDescriptor
import com.ibm.security.verifysdk.mfa.MFAServiceException
import com.ibm.security.verifysdk.mfa.NextTransactionInfo
import com.ibm.security.verifysdk.mfa.PendingTransactionInfo
import com.ibm.security.verifysdk.mfa.R
import com.ibm.security.verifysdk.mfa.TransactionAttribute
import com.ibm.security.verifysdk.mfa.UserAction
import com.ibm.security.verifysdk.mfa.model.onprem.TransactionResult
import com.ibm.security.verifysdk.mfa.model.onprem.VerificationInfo
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.get
import io.ktor.client.request.patch
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.content.TextContent
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import org.slf4j.LoggerFactory
import java.net.URL
import java.util.UUID
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

/**
 * Immutable on-premise MFA authenticator service.
 *
 * ## Design Philosophy
 * This service is an **immutable value object** that represents a snapshot of authenticator
 * state at a specific point in time, consistent with CloudAuthenticatorService design.
 *
 * ## Lifecycle Pattern
 * ```kotlin
 * // 1. Create service with current token
 * val service = OnPremiseAuthenticatorService(
 *     _accessToken = authenticator.token.accessToken,
 *     _refreshUri = authenticator.refreshUri,
 *     _transactionUri = authenticator.transactionUri,
 *     _clientId = authenticator.clientId,
 *     _authenticatorId = authenticator.id,
 *     httpClient = NetworkHelper.getInstance,
 *     _ignoreSslCertificate = authenticator.ignoreSslCertificate,
 *     persistenceCallback = repository
 * )
 *
 * // 2. Use service for operations
 * service.nextTransaction()
 * service.completeTransaction(...)
 *
 * // 3. If token is refreshed, create NEW service
 * service.refreshToken(...).onSuccess { newToken ->
 *     // This service is now obsolete!
 *     val newService = OnPremiseAuthenticatorService(
 *         _accessToken = newToken.accessToken,  // New token
 *         _refreshUri = authenticator.refreshUri,
 *         _transactionUri = authenticator.transactionUri,
 *         _clientId = authenticator.clientId,
 *         _authenticatorId = authenticator.id,
 *         httpClient = NetworkHelper.getInstance,
 *         _ignoreSslCertificate = authenticator.ignoreSslCertificate,
 *         persistenceCallback = repository
 *     )
 *     // Use newService for subsequent operations
 * }
 * ```
 *
 * @property _accessToken The OAuth access token (immutable snapshot)
 * @property _refreshUri The endpoint URL for token refresh operations
 * @property _transactionUri The endpoint URL for transaction operations
 * @property _clientId The OAuth client ID
 * @property _authenticatorId The unique identifier for this authenticator
 * @property httpClient The HTTP client for making network requests
 * @property _ignoreSslCertificate Whether to ignore SSL certificate validation
 * @property persistenceCallback Optional callback for automatic token persistence
 */
@OptIn(ExperimentalTime::class)
class OnPremiseAuthenticatorService(
    private val _accessToken: String,
    private val _refreshUri: URL,
    private val _transactionUri: URL,
    private val _clientId: String,
    private val _authenticatorId: String,
    internal val httpClient: HttpClient,
    private val _ignoreSslCertificate: Boolean = false,
    private val persistenceCallback: com.ibm.security.verifysdk.mfa.TokenPersistenceCallback? = null
) : MFAServiceDescriptor {

    private val log = LoggerFactory.getLogger(javaClass)
    private val decoder = Json {
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    override val accessToken: String
        get() = _accessToken

    override val refreshUri: URL
        get() = _refreshUri

    override val transactionUri: URL
        get() = _transactionUri

    override val authenticatorId: String
        get() = _authenticatorId

    val clientId: String
        get() = _clientId

    val ignoreSslCertificate: Boolean
        get() = _ignoreSslCertificate

    /**
     * Refreshes the OAuth token with **CRITICAL** persistence guarantees.
     *
     * ## ⚠️ CRITICAL: Token Persistence
     *
     * This method implements **BLOCKING, ATOMIC** token persistence to prevent the
     * "hosed authenticator" scenario.
     *
     * ## Service Lifecycle
     * **IMPORTANT:** This service instance becomes obsolete after token refresh.
     * You must create a new service instance with the new token.
     *
     * @see CloudAuthenticatorService.refreshToken for detailed documentation
     */
    override suspend fun refreshToken(
        refreshToken: String,
        accountName: String?,
        pushToken: String?,
        additionalData: Map<String, Any>?
    ): Result<TokenInfo> {

        return try {
            log.entering()
            val attributes =
                MFAAttributeInfo.dictionary(snakeCaseKey = true).toMutableMap()
            accountName?.let {
                attributes["accountName"] = it
            }
            pushToken?.let {
                attributes["pushToken"] = it
            }
            attributes["tenant_id"] = authenticatorId
            additionalData?.let {
                attributes.putAll(it)
            }

            val oAuthProvider = OAuthProvider(
                clientId = clientId,
                additionalParameters = attributes.toMap()
                    .mapValues { entry -> entry.value.toString() }
                    .toMutableMap()
            )
            if (ignoreSslCertificate) {
                // disable SSL validations for network client
            }

            val responseToken = oAuthProvider.refresh(
                url = refreshUri,
                refreshToken = refreshToken,
                httpClient = httpClient
            )

            responseToken.also { result ->
                // Don't mutate state - service is immutable
                // Repository layer creates new service instance with new token
                result.onSuccess { tokenInfo ->
                    // CRITICAL: Persist token BEFORE returning success
                    // This ensures token is saved BEFORE any subsequent API call that would activate it on server
                    persistenceCallback?.let { callback ->
                        val persistResult = callback.onTokenRefreshed(authenticatorId, tokenInfo)
                        persistResult.onFailure { error ->
                            log.error("CRITICAL: Token persistence failed for authenticator $_authenticatorId: ${error.message}")
                            // Return failure if persistence fails - token refresh is not complete without persistence
                            return Result.failure(
                                Exception(
                                    "Token refresh succeeded but persistence failed: ${error.message}",
                                    error
                                )
                            )
                        }
                        log.debug("Token persisted successfully for authenticator $_authenticatorId")
                    }
                }
            }
        } catch (e: Throwable) {
            Result.failure(e)
        } finally {
            log.exiting()
        }
    }

    override suspend fun nextTransaction(
        transactionID: String?
    ): Result<NextTransactionInfo> {

        return try {
            log.entering()
            val response = httpClient.get {
                url(transactionUri.toString())
                accept(ContentType.Application.Json)
                bearerAuth(accessToken)
            }

            if (response.status.isSuccess()) {
                val transactionResult = decoder.decodeFromString(
                    TransactionResult.TransactionResultSerializer,
                    response.bodyAsText()
                )
                if (transactionResult.transactions.isEmpty()) {
                    Result.success(NextTransactionInfo(emptyList(), 0))
                } else {
                    val transactions = createPendingTransactions(transactionResult, transactionID)
                    Result.success(
                        NextTransactionInfo(
                            transactions,
                            transactionResult.transactions.count()
                        )
                    )
                }
            } else {
                Result.failure(MFAServiceException.InvalidDataResponse())
            }
        } catch (e: Throwable) {
            Result.failure(e)
        } finally {
            log.exiting()
        }
    }

    override suspend fun completeTransaction(
        transaction: PendingTransactionInfo,
        userAction: UserAction,
        signedData: String
    ): Result<Unit> {

        return try {
            // Validate transaction hasn't expired
            transaction.expiryTime?.let { expiry ->
                if (kotlin.time.Clock.System.now() > expiry) {
                    return Result.failure(
                        MFAServiceException.General("Transaction ${transaction.id} has expired at $expiry")
                    )
                }
            }

            val data = buildJsonObject {
                put(
                    "signedChallenge",
                    if (userAction == UserAction.VERIFY) JsonPrimitive(signedData) else JsonPrimitive(
                        ""
                    )
                )

                // Add denyReason if denyReasonEnabled flag is set to "true"
                val denyReasonEnabled = transaction.additionalData[TransactionAttribute.DenyReason]
                if (denyReasonEnabled == "true") {
                    put("denyReason", JsonPrimitive(userAction.toString()))
                }
            }

            val response = httpClient.put {
                url(transaction.postbackUri.toString())
                accept(ContentType.Application.Json)
                bearerAuth(accessToken)
                setBody(TextContent(data.toString(), ContentType.Application.Json))
            }

            if (response.status.isSuccess()) {
                Result.success(Unit)
            } else {
                Result.failure(
                    MFAServiceException.General(
                        "Failed to complete transaction ${transaction.id}: ${response.bodyAsText()}"
                    )
                )
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            // Don't wrap cancellation exceptions
            throw e
        } catch (e: Exception) {
            Result.failure(
                MFAServiceException.General(
                    "Exception while completing transaction ${transaction.id}: ${e.message}",
                    e
                )
            )
        }
    }

    suspend fun remove(httpClient: HttpClient = NetworkHelper.getInstance): Result<Unit> {

        return try {
            log.entering()
            val data = buildJsonObject {
                put("schemas", buildJsonArray {
                    add(JsonPrimitive("urn:ietf:params:scim:api:messages:2.0:PatchOp"))
                })
                put("Operations", buildJsonArray {
                    add(buildJsonObject {
                        put("op", JsonPrimitive("remove"))
                        put(
                            "path",
                            JsonPrimitive("urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:authenticators[id eq ${authenticatorId}]")
                        )
                    })
                })
            }

            val updateUrl = createUpdateUrl(transactionUri)

            val response = httpClient.patch {
                url(updateUrl)
                accept(ContentType.Application.Json)
                bearerAuth(accessToken)
                setBody(TextContent(data.toString(), ContentType.Application.Json))

            }

            if (response.status.isSuccess()) {
                Result.success(Unit)
            } else {
                response.bodyAsText().let { responseBody ->
                    if (responseBody.isEmpty()) {
                        Result.failure(MFAServiceException.InvalidDataResponse())
                    } else {
                        Result.failure(MFAServiceException.General(responseBody))
                    }
                }
            }
        } finally {
            log.exiting()
        }
    }

    private suspend fun createPendingTransactions(
        transactionResult: TransactionResult,
        transactionId: String? = null
    ): List<PendingTransactionInfo> {
        // Get identifiers for this authenticator
        val identifiers = transactionResult.attributes.filter {
            it.uri == "mmfa:request:authenticator:id" && it.values.contains(authenticatorId)
        }

        // Get all transaction IDs for this authenticator
        val transactionIds = if (transactionId != null) {
            // If specific transaction requested, only get that one
            listOf(transactionId)
        } else if (identifiers.isNotEmpty()) {
            // Get all transactions for this authenticator
            identifiers.map { it.transactionId }
        } else {
            // Fallback to all transactions
            transactionResult.transactions.map { it.transactionId }
        }

        val now = Clock.System.now()

        return transactionIds.mapNotNull { txnId ->
            val result = createPendingTransaction(transactionResult, txnId)
            result.getOrNull()?.let { transaction ->
                // Filter out expired transactions
                transaction.expiryTime?.let { expiry ->
                    if (now > expiry) {
                        return@mapNotNull null
                    }
                }
                transaction
            }
        }
    }

    private suspend fun createPendingTransaction(
        transactionResult: TransactionResult,
        transactionId: String
    ): Result<PendingTransactionInfo> {

        return try {
            log.entering()
            // Get the specific transaction
            val transactionInfoResult = transactionResult.transactions.firstOrNull {
                it.transactionId == transactionId
            }
                ?: return Result.failure(MFAServiceException.General("Transaction not found: $transactionId"))

            val response = httpClient.post {
                url(transactionInfoResult.requestUrl)
                contentType(ContentType.Application.Json)
                accept(ContentType.Application.Json)
                bearerAuth(accessToken)
            }

            if (response.status.isSuccess()) {
                val verificationInfo =
                    decoder.decodeFromString<VerificationInfo>(response.bodyAsText())

                // Extract expiry time from attributesPending array
                // Look for mmfa.transactionPending.minAgeBeforeAbort attribute
                val expirySeconds = transactionResult.attributes
                    .firstOrNull {
                        it.transactionId == transactionInfoResult.transactionId &&
                                it.uri == "mmfa.transactionPending.minAgeBeforeAbort"
                    }
                    ?.values?.firstOrNull()?.toLongOrNull() ?: 300L

                val calculatedExpiryTime =
                    transactionInfoResult.creationTime + expirySeconds.seconds

                var dataToSign = verificationInfo.serverChallenge
                if (transactionResult.attributes.any { it.uri == "mmfa:request:signing:attributes" }) {
                    val signingInfo =
                        transactionResult.attributes.first { it.uri == "mmfa:request:signing:attributes" }
                    val value = signingInfo.values.first()
                    dataToSign = value
                }
                val attributeInfo =
                    transactionResult.attributes.filter {
                        it.transactionId == transactionInfoResult.transactionId &&
                                (it.uri == "mmfa:request:context:message" || it.uri == "mmfa:request:extras")
                    }
                var verificationMessage =
                    ContextHelper.context.getString(R.string.PendingRequestMessageDefault)
                attributeInfo.firstOrNull { it.uri == "mmfa:request:context:message" }?.values?.firstOrNull()
                    ?.let {
                        verificationMessage = it
                    }
                val postbackUri = createPostBackUrl(
                    URL(transactionInfoResult.requestUrl),
                    verificationInfo.location
                )

                Result.success(
                    PendingTransactionInfo(
                        id = transactionInfoResult.transactionId,
                        message = verificationMessage,
                        postbackUri = postbackUri,
                        factorID = UUID(0, 0), // not used for OnPrem
                        factorType = verificationInfo.type,
                        dataToSign = dataToSign,
                        creationTime = transactionInfoResult.creationTime,
                        expiryTime = calculatedExpiryTime,
                        additionalData = createAdditionalData(attributeInfo)
                    )
                )
            } else {
                Result.failure(MFAServiceException.InvalidDataResponse())
            }
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            log.exiting()
        }
    }

    private fun createPostBackUrl(
        transactionRequestUrl: URL,
        verificationInfoLocation: String
    ): URL {
        return URL(
            Uri.Builder().scheme((transactionRequestUrl.protocol))
                .encodedAuthority(transactionRequestUrl.authority)
                .appendEncodedPath(verificationInfoLocation)
                .build()
                .toString()
        )
    }

    private fun createUpdateUrl(
        transactionUri: URL
    ): URL {
        return URL(
            Uri.Builder().scheme((transactionUri.protocol))
                .encodedAuthority(transactionUri.authority)
                .appendEncodedPath(transactionUri.path)
                .appendQueryParameter(
                    "attributes",
                    "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:authenticators"
                )
                .build()
                .toString()
        )
    }

//    {
//        "dataType":"String",
//        "values":[
//        "PM: Please verify login to mmfa.securitypoc.com"
//        ],
//        "name":"mmfa.request.push.message",
//        "uri":"mmfa:request:push:message",
//        "transactionId":"c15e351e-b2c1-493f-9a08-b03ee51b5ad8"
//    },

//    @Serializable
//    data class AttributeInfo(
//        val dataType: String,
//        val values: List<String>,
//        val uri: String,
//        val transactionId: String
//    )

//    IPAddress("ipAddress"),
//    Location("location"),
//    Image("image"),
//    UserAgent("userAgent"),
//    Type("type"),
//    Custom("custom")

    /**
     * Calculates a correlation value from a transaction ID.
     *
     * The correlation value is a 2-digit number (00-99) derived from the transaction ID
     * by taking the first 8 characters, parsing them as hexadecimal, and calculating
     * modulo 100. This value is used to help users verify they are approving the correct
     * transaction by matching it with a value displayed in the requesting application.
     *
     * @param transactionId The transaction ID to calculate the correlation value from
     * @return A 2-digit string representation of the correlation value (00-99),
     *         or "00" if calculation fails
     */
    private fun calculateCorrelationValue(transactionId: String): String {
        return try {
            // Take first 8 characters of transaction ID
            val shortTransactionId = transactionId.substring(0, minOf(transactionId.length, 8))
            // Parse as hexadecimal and calculate modulo 100
            val correlationValue = shortTransactionId.toBigInteger(16).mod(100.toBigInteger())

            // Format with leading zero if less than 10
            if (correlationValue > 9.toBigInteger()) {
                correlationValue.toString()
            } else {
                "0${correlationValue}"
            }
        } catch (e: Exception) {
            log.warn("Failed to calculate correlation value: ${e.message}")
            "00"
        }
    }

    private fun createAdditionalData(attributeInfos: List<TransactionResult.AttributeInfo>): Map<TransactionAttribute, String> {

        return try {
            log.entering()
            val result = mutableMapOf<TransactionAttribute, String>()
            var transactionId: String? = null

            // Get transaction ID from attributes
            attributeInfos.firstOrNull()?.let {
                transactionId = it.transactionId
            }

            attributeInfos.filter { it.uri == "mmfa:request:extras" }.forEach { attributeInfo ->
                // Parse JSON string from values if dataType is "String"
                if (attributeInfo.dataType.equals(
                        "String",
                        ignoreCase = true
                    ) && attributeInfo.values.isNotEmpty()
                ) {
                    try {
                        val jsonString = attributeInfo.values.first()
                        val jsonElement = Json.parseToJsonElement(jsonString).jsonObject

                        // Extract and handle correlationEnabled (can be Boolean or String)
                        var isCorrelationEnabled = false
                        jsonElement["correlationEnabled"]?.let { element ->
                            if (element is JsonPrimitive) {
                                isCorrelationEnabled = when {
                                    element.isString -> element.content.toBoolean()
                                    else -> element.content.toBoolean()
                                }
                            }
                        }

                        // If correlation is enabled, extract or calculate correlation value
                        if (isCorrelationEnabled) {
                            val correlation = jsonElement["correlationValue"]?.let { element ->
                                if (element is JsonPrimitive) {
                                    element.content
                                } else null
                            } ?: transactionId?.let { calculateCorrelationValue(it) } ?: "00"

                            result[TransactionAttribute.Correlation] = correlation
                        }

                        // Extract and handle denyReasonEnabled (can be Boolean or String)
                        jsonElement["denyReasonEnabled"]?.let { element ->
                            if (element is JsonPrimitive) {
                                val isDenyReasonEnabled = when {
                                    element.isString -> element.content.toBoolean()
                                    else -> element.content.toBoolean()
                                }
                                result[TransactionAttribute.DenyReason] =
                                    isDenyReasonEnabled.toString()
                            }
                        }
                    } catch (e: Exception) {
                        log.warn("Failed to parse mmfa:request:extras JSON: ${e.message}")
                    }
                }

                if (attributeInfo.dataType.equals("type", ignoreCase = true)) {
                    result[TransactionAttribute.Type] = attributeInfo.values.first()
                }
                if (attributeInfo.dataType.equals("originIpAddress", ignoreCase = true)) {
                    result[TransactionAttribute.IPAddress] = attributeInfo.values.first()
                }
                if (attributeInfo.dataType.equals("originLocation", ignoreCase = true)) {
                    result[TransactionAttribute.Location] = attributeInfo.values.first()
                }
                if (attributeInfo.dataType.equals("originUserAgent", ignoreCase = true)) {
                    result[TransactionAttribute.UserAgent] = attributeInfo.values.first()
                }
                if (attributeInfo.dataType.equals("imageURL", ignoreCase = true)) {
                    result[TransactionAttribute.Image] = attributeInfo.values.first()
                }

            }
            result
        } finally {
            log.exiting()
        }


    }
}