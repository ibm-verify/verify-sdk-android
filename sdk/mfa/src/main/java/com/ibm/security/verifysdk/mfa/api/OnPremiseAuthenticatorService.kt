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
import com.ibm.security.verifysdk.mfa.MFAServiceError
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
import org.slf4j.LoggerFactory
import java.net.URL
import java.util.UUID
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@OptIn(ExperimentalTime::class)
class OnPremiseAuthenticatorService(
    private var _accessToken: String,
    private var _refreshUri: URL,
    private var _transactionUri: URL,
    private var _clientId: String,
    private var _authenticatorId: String,
    private var _ignoreSslCertificate: Boolean = false

) : MFAServiceDescriptor {

    private val log = LoggerFactory.getLogger(javaClass)
    private val decoder =  Json {
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    private lateinit var _currentPendingTransaction: PendingTransactionInfo

    override val accessToken: String
        get() = _accessToken

    override val refreshUri: URL
        get() = _refreshUri

    override val transactionUri: URL
        get() = _transactionUri

    override val currentPendingTransaction: PendingTransactionInfo?
        get() = _currentPendingTransaction

    override val authenticatorId: String
        get() = _authenticatorId

    val clientId: String
        get() = _clientId

    val ignoreSslCertificate: Boolean
        get() = _ignoreSslCertificate

    override suspend fun refreshToken(
        refreshToken: String,
        accountName: String?,
        pushToken: String?,
        additionalData: Map<String, Any>?,
        httpClient: HttpClient
    ): Result<TokenInfo> {

        return try {
            log.entering()
            val attributes =
                MFAAttributeInfo.init(ContextHelper.context).dictionary(snakeCaseKey = true)
                    .toMutableMap()
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

            responseToken.fold(
                onSuccess = { tokenInfo ->
                    Result.success(tokenInfo)
                },
                onFailure = { throwable ->
                    Result.failure(throwable)
                })
        } catch (e: Throwable) {
            Result.failure(e)
        } finally {
            log.exiting()
        }
    }

    override suspend fun nextTransaction(transactionID: String?, httpClient: HttpClient): Result<NextTransactionInfo> {

        return try {
            log.entering()
            val response =httpClient.get {
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
                    Result.success(NextTransactionInfo(null, 0))
                } else {
                    createPendingTransaction(transactionResult, transactionID, httpClient).fold(
                        onSuccess = { pendingTransactionInfo ->
                            _currentPendingTransaction = pendingTransactionInfo
                            Result.success(
                                NextTransactionInfo(
                                    pendingTransactionInfo,
                                    transactionResult.transactions.count()
                                )
                            )
                        },
                        onFailure = { throwable ->
                            Result.failure(throwable)
                        }
                    )
                }
            } else {
                Result.failure(MFAServiceError.InvalidDataResponse())
            }
        } catch (e: Throwable) {
            Result.failure(e)
        } finally {
            log.exiting()
        }
    }

    override suspend fun completeTransaction(
        userAction: UserAction,
        signedData: String,
        httpClient: HttpClient
    ): Result<Unit> {

        return try {
            val pendingTransaction =
                currentPendingTransaction ?: throw MFAServiceError.InvalidPendingTransaction()

            val data = buildJsonObject {
                put(
                    "signedChallenge",
                    if (userAction == UserAction.VERIFY) JsonPrimitive(signedData) else JsonNull
                )
            }

            val response = httpClient.put {
                url(pendingTransaction.postbackUri.toString())
                accept(ContentType.Application.Json)
                bearerAuth(accessToken)
                setBody(TextContent(data.toString(), ContentType.Application.Json))
            }

            if (response.status.isSuccess()) {
                Result.success(Unit)
            } else {
                Result.failure(MFAServiceError.General(response.bodyAsText()))
            }
        } catch (e: Throwable) {
            return Result.failure(e)
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
                        Result.failure(MFAServiceError.InvalidDataResponse())
                    } else {
                        Result.failure(MFAServiceError.General(responseBody))
                    }
                }
            }
        } finally {
            log.exiting()
        }
    }

    private suspend fun createPendingTransaction(
        transactionResult: TransactionResult,
        transactionId: String? = null,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<PendingTransactionInfo> {

        return try {
            log.entering()
            /* Optional variable to hold the transaction. By default, we'll store the first transaction
           encountered but reassign if we match the authenticatorId and/or transactionId. */
            var transactionInfoResult =
                transactionResult.transactions.firstOrNull { it.transactionId == transactionId }
                    ?: transactionResult.transactions.first()
            /* Get a list of attributesPending that contain mmfa:request:authenticator:id. */
            val identifiers =
                transactionResult.attributes.filter { it.uri == "mmfa:request:authenticator:id" }

            if (identifiers.any { it.values.contains(authenticatorId) }) {
                val identifier = identifiers.first { it.values.contains(authenticatorId) }
                /* If a transactionId was passed in as a parameter, get that one, otherwise get the
               first transaction for the authenticator. */
                transactionInfoResult = if (transactionId != null) {
                    transactionResult.transactions.first { it.transactionId == transactionId }
                } else {
                    transactionResult.transactions.first { it.transactionId == identifier.transactionId }
                }
            }

            val response = httpClient.post {
                url(transactionInfoResult.requestUrl)
                contentType(ContentType.Application.Json)
                accept(ContentType.Application.Json)
                bearerAuth(accessToken)
            }

            if (response.status.isSuccess()) {
                val verificationInfo =
                    decoder.decodeFromString<VerificationInfo>(response.bodyAsText())
                var dataToSign = verificationInfo.serverChallenge
                if (transactionResult.attributes.any { it.uri == "mmfa:request:signing:attributes" }) {
                    val signingInfo =
                        transactionResult.attributes.first { it.uri == "mmfa:request:signing:attributes" }
                    val value = signingInfo.values.first()
                    dataToSign = value
                }
                val attributeInfo =
                    transactionResult.attributes.filter { it.transactionId == transactionInfoResult.transactionId &&
                            (it.uri == "mmfa:request:context:message" || it.uri == "mmfa:request:extras") }
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
                        timeStamp = transactionInfoResult.creationTime,
                        additionalData = createAdditionalData(attributeInfo)
                    )
                )
            } else {
                Result.failure(MFAServiceError.InvalidDataResponse())
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

    private fun createAdditionalData(attributeInfos: List<TransactionResult.AttributeInfo>): Map<TransactionAttribute, String> {

        return try {
            log.entering()
            val result = mutableMapOf<TransactionAttribute, String>()

            attributeInfos.filter { it.uri == "mmfa:request:extras" }.forEach { attributeInfo ->
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