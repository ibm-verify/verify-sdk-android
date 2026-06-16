/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import android.net.Uri
import com.ibm.security.verifysdk.authentication.api.OAuthProvider
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.extension.entering
import com.ibm.security.verifysdk.core.extension.exiting
import com.ibm.security.verifysdk.core.extension.logError
import com.ibm.security.verifysdk.core.extension.logInfo
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
import kotlinx.coroutines.CancellationException
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
 *     _serverAuthenticatorId = authenticator.token.additionalData["authenticator_id"] as? String,
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
 *         _serverAuthenticatorId = newToken.additionalData["authenticator_id"] as? String,
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
 * @property _authenticatorId The unique identifier for this authenticator (tenant_id)
 * @property _serverAuthenticatorId The server's authenticator ID for transaction filtering (optional)
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
    private val _serverAuthenticatorId: String? = null,
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

    companion object {
        private const val TAG = "OnPremAuthService"
    }

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
                attributes["account_name"] = it
            }
            pushToken?.let {
                attributes["push_token"] = it
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
            // Note: SSL certificate bypass is handled at the HTTP client level
            // The httpClient passed to this service is already configured for SSL bypass if needed

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
                        log.error("Token persisted successfully for authenticator $_authenticatorId")
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
            log.error("nextTransaction called with transactionID: $transactionID")
            log.error("nextTransaction - _authenticatorId: $_authenticatorId")
            log.error("nextTransaction - _serverAuthenticatorId: $_serverAuthenticatorId")
            log.error("nextTransaction - transactionUri: $transactionUri")
            log.error("nextTransaction - accessToken length: ${accessToken.length}")

            val response = httpClient.get {
                url(transactionUri.toString())
                accept(ContentType.Application.Json)
                bearerAuth(accessToken)
            }

            log.error("nextTransaction - HTTP response status: ${response.status}")
            log.error("nextTransaction - HTTP response body length: ${response.bodyAsText().length}")

            if (response.status.isSuccess()) {
                val responseBody = response.bodyAsText()
                log.error("nextTransaction - Response body: $responseBody")

                val transactionResult = decoder.decodeFromString(
                    TransactionResult.TransactionResultSerializer,
                    responseBody
                )

                log.error("nextTransaction - Decoded transactions count: ${transactionResult.transactions.size}")
                transactionResult.transactions.forEachIndexed { index, txn ->
                    log.error("nextTransaction - Transaction[$index] transactionId: ${txn.transactionId}")
                    log.error("nextTransaction - Transaction[$index] creationTime: ${txn.creationTime}")
                    log.error("nextTransaction - Transaction[$index] requestUrl: ${txn.requestUrl}")
                    log.error("nextTransaction - Transaction[$index] authnPolicyUri: ${txn.authnPolicyUri}")
                }

                if (transactionResult.transactions.isEmpty()) {
                    log.error("nextTransaction - No transactions from server, returning empty list")
                    Result.success(NextTransactionInfo(emptyList(), 0))
                } else {
                    log.error("nextTransaction - Calling createPendingTransactions with transactionID: $transactionID")
                    val transactions = createPendingTransactions(transactionResult, transactionID)
                    log.error("nextTransaction - createPendingTransactions returned ${transactions.size} transactions")
                    transactions.forEachIndexed { index, pending ->
                        log.error("nextTransaction - PendingTransaction[$index] id: ${pending.id}")
                        log.error("nextTransaction - PendingTransaction[$index] message: ${pending.message}")
                    }

                    val result = Result.success(
                        NextTransactionInfo(
                            transactions,
                            transactionResult.transactions.count()
                        )
                    )
                    log.error("nextTransaction - Returning success with ${transactions.size} pending, ${transactionResult.transactions.count()} total")
                    result
                }
            } else {
                log.error("nextTransaction - HTTP request failed with status: ${response.status}")
                Result.failure(MFAServiceException.InvalidDataResponse())
            }
        } catch (e: Throwable) {
            log.error("nextTransaction - Exception caught: ${e.message}", e)
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
                    put("userAction", JsonPrimitive(userAction.value))
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
        } catch (e: CancellationException) {
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

    /**
     * Performs QR code login for OnPremise authenticators.
     *
     * This function sends a login request to the OnPremise server using the provided
     * QR login endpoint and login session identifier (lsi). The request is authenticated
     * using the authenticator's OAuth access token.
     *
     * ## Usage Example
     * ```kotlin
     * val service = OnPremiseAuthenticatorService(...)
     * val result = service.login(
     *     qrLoginEndpoint = "https://onprem.company.com/mga/sps/mmfa/user/mgmt/login",
     *     code = "abc123xyz"  // The lsi from QR code
     * )
     *
     * result.onSuccess {
     *     // Login successful
     * }.onFailure { error ->
     *     // Handle error
     * }
     * ```
     *
     * @param qrLoginEndpoint The full URL of the OnPremise login endpoint
     * @param code The login session identifier (lsi) from the QR code
     *
     * @return A [Result] containing either:
     *         - Success: Unit indicating the login was successful
     *         - Failure: An exception indicating why the login failed
     *
     * @throws kotlinx.coroutines.CancellationException if the coroutine is cancelled
     * @throws MFAServiceException.General if the request fails
     *
     * @see com.ibm.security.verifysdk.mfa.model.onprem.OnPremiseAuthenticator
     */
    suspend fun login(
        qrLoginEndpoint: String,
        code: String
    ): Result<Unit> {
        return try {
            log.entering()
            logInfo(TAG) { "Starting QR code login for authenticator $authenticatorId" }

            // Build JSON payload with the lsi code (same as v2 implementation)
            val jsonBody = buildJsonObject {
                put("lsi", JsonPrimitive(code))
            }

            // Make POST request to login endpoint
            val response = httpClient.post {
                url(qrLoginEndpoint)
                bearerAuth(accessToken)
                contentType(ContentType.Application.Json)
                accept(ContentType.Application.Json)
                setBody(TextContent(jsonBody.toString(), ContentType.Application.Json))
            }

            // Handle response
            if (response.status.isSuccess()) {
                logInfo(TAG) { "QR code login successful for authenticator $authenticatorId" }
                Result.success(Unit)
            } else {
                val errorBody = response.bodyAsText()
                logError(TAG) { "QR code login failed for authenticator $authenticatorId: ${response.status} - $errorBody" }

                // Parse error response if available
                val errorMessage = try {
                    val json = Json { ignoreUnknownKeys = true }
                    val errorResponse = json.parseToJsonElement(errorBody).jsonObject
                    errorResponse["error_description"]?.toString()?.trim('"')
                        ?: errorResponse["error"]?.toString()?.trim('"')
                        ?: "Login failed with status ${response.status.value}"
                } catch (e: Exception) {
                    "Login failed with status ${response.status.value}"
                }

                Result.failure(
                    MFAServiceException.General(errorMessage)
                )
            }
        } catch (e: CancellationException) {
            // Don't wrap cancellation exceptions
            throw e
        } catch (e: Exception) {
            logError(TAG, e) { "Exception during QR code login for authenticator $authenticatorId" }
            Result.failure(
                MFAServiceException.General(
                    "Exception during login: ${e.message}",
                    e
                )
            )
        } finally {
            log.exiting()
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
        log.error("=== createPendingTransactions START ===")
        log.error("Requested specific transaction: ${transactionId ?: "ALL"}")
        log.error("Client authenticator ID (_authenticatorId): $_authenticatorId")
        log.error("Server authenticator ID (_serverAuthenticatorId): $_serverAuthenticatorId")

        // Use server's authenticator_id for filtering transactions
        // If not available, return empty list as transactions won't match tenant_id
        val filterAuthenticatorId = _serverAuthenticatorId

        if (filterAuthenticatorId == null) {
            log.error("❌ No server authenticator_id available for filtering transactions")
            log.error("=== createPendingTransactions END: 0 transactions ===")
            return emptyList()
        }

        log.error("Using filter authenticator ID: $filterAuthenticatorId")

        // Log all authenticator IDs in the transaction result
        val allAuthenticatorIds = transactionResult.attributes
            .filter { it.uri == "mmfa:request:authenticator:id" }
        log.error("Found ${allAuthenticatorIds.size} authenticator ID attributes in transaction result:")
        allAuthenticatorIds.forEach { attr ->
            log.error("  - Transaction ${attr.transactionId}: ${attr.values.joinToString(", ")}")
        }

        // Get identifiers for this authenticator
        val identifiers = transactionResult.attributes.filter {
            it.uri == "mmfa:request:authenticator:id" && it.values.contains(filterAuthenticatorId)
        }

        log.error("Matched ${identifiers.size} identifier(s) for authenticator $filterAuthenticatorId")
        identifiers.forEach { id ->
            log.error("  - Matched transaction: ${id.transactionId}")
        }

        // Get all transaction IDs for this authenticator
        val transactionIds = if (transactionId != null) {
            log.error("Specific transaction requested: $transactionId")
            // If specific transaction requested, validate it belongs to this authenticator first
            val belongsToThisAuthenticator = transactionResult.attributes.any {
                it.transactionId == transactionId &&
                        it.uri == "mmfa:request:authenticator:id" &&
                        it.values.contains(filterAuthenticatorId)
            }
            if (belongsToThisAuthenticator) {
                log.error("✓ Transaction $transactionId belongs to this authenticator")
                listOf(transactionId)
            } else {
                log.error("❌ Transaction $transactionId does not belong to authenticator $filterAuthenticatorId")
                emptyList()
            }
        } else if (identifiers.isNotEmpty()) {
            // Get all transactions for this authenticator
            val ids = identifiers.map { it.transactionId }
            log.error(
                "✓ Found ${ids.size} transaction(s) for this authenticator: ${
                    ids.joinToString(
                        ", "
                    )
                }"
            )
            ids
        } else {
            // No transactions for this authenticator - return empty list
            // This prevents attempting to process transactions that belong to other authenticators
            log.error("❌ No transactions found for authenticator $filterAuthenticatorId")
            emptyList()
        }

        log.error("Processing ${transactionIds.size} transaction ID(s)")

        val now = Clock.System.now()
        log.error("Current time: $now")

        val pendingTransactions = transactionIds.mapNotNull { txnId ->
            log.error("Creating pending transaction for ID: $txnId")
            val result = createPendingTransaction(transactionResult, txnId)
            result.fold(
                onSuccess = { transaction ->
                    log.error("✓ Successfully created transaction object for $txnId")
                    // Filter out expired transactions
                    transaction.expiryTime?.let { expiry ->
                        log.error("  Transaction expiry: $expiry")
                        if (now > expiry) {
                            log.error("  ❌ Transaction $txnId is EXPIRED (now: $now > expiry: $expiry)")
                            return@mapNotNull null
                        } else {
                            log.error("  ✓ Transaction $txnId is NOT expired")
                        }
                    } ?: log.error("  ℹ Transaction $txnId has no expiry time")
                    transaction
                },
                onFailure = { error ->
                    log.error("❌ Failed to create transaction object for $txnId: ${error.message}")
                    null
                }
            )
        }

        log.error("=== createPendingTransactions END: ${pendingTransactions.size} transaction(s) ===")
        return pendingTransactions
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

                // Validate that this transaction belongs to this authenticator
                // This prevents one authenticator from attempting to complete another's transaction
                val authenticatorIdAttribute = transactionResult.attributes.firstOrNull {
                    it.transactionId == transactionInfoResult.transactionId &&
                            it.uri == "mmfa:request:authenticator:id"
                }

                if (authenticatorIdAttribute != null) {
                    if (!authenticatorIdAttribute.values.contains(_serverAuthenticatorId)) {
                        log.error("Transaction $transactionId does not belong to authenticator $_serverAuthenticatorId")
                        return Result.failure(
                            MFAServiceException.General(
                                "Transaction $transactionId does not belong to authenticator $_serverAuthenticatorId"
                            )
                        )
                    }
                }

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
                        // Handle malformed JSON with single quotes by replacing them with double quotes
                        // This is a workaround for servers that send invalid JSON format
                        val normalizedJsonString = jsonString.replace('\'', '"')
                        val jsonElement = Json.parseToJsonElement(normalizedJsonString).jsonObject

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