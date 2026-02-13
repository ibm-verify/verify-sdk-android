/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.extension.camelToSnakeCase
import com.ibm.security.verifysdk.core.extension.entering
import com.ibm.security.verifysdk.core.extension.exiting
import com.ibm.security.verifysdk.core.extension.replaceInPath
import com.ibm.security.verifysdk.core.extension.snakeToCamelCase
import com.ibm.security.verifysdk.core.extension.toJsonObject
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.mfa.BiometricFactorInfo
import com.ibm.security.verifysdk.mfa.EnrollableType
import com.ibm.security.verifysdk.mfa.HashAlgorithmException
import com.ibm.security.verifysdk.mfa.HashAlgorithmType
import com.ibm.security.verifysdk.mfa.MFAAttributeInfo
import com.ibm.security.verifysdk.mfa.MFAAuthenticatorDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationException
import com.ibm.security.verifysdk.mfa.RegistrationInitiation
import com.ibm.security.verifysdk.mfa.SignatureEnrollableFactor
import com.ibm.security.verifysdk.mfa.UserPresenceFactorInfo
import com.ibm.security.verifysdk.mfa.generateKeys
import com.ibm.security.verifysdk.mfa.model.cloud.CloudAuthenticator
import com.ibm.security.verifysdk.mfa.model.cloud.CloudRegistration
import com.ibm.security.verifysdk.mfa.model.cloud.CloudRegistrationProviderResultData
import com.ibm.security.verifysdk.mfa.model.cloud.InitializationInfo
import com.ibm.security.verifysdk.mfa.model.cloud.Metadata
import com.ibm.security.verifysdk.mfa.sign
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.content.TextContent
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.json.JSONArray
import org.json.JSONObject
import org.slf4j.LoggerFactory
import java.net.URL
import java.util.UUID

/**
 * Provider for cloud-based MFA registration with IBM Verify instances or custom mobile authenticators.
 */
class CloudRegistrationProvider(data: String) :
    MFARegistrationDescriptor<MFAAuthenticatorDescriptor> {

    companion object {
        /**
         * Initiate an authenticator registration for IBM Verify instances or custom mobile authenticators.
         *
         * @param initiateUri The endpoint location to initiate a multi-factor device registration.
         * @param accessToken The authenticated user token.
         * @param clientId The unique identifier of the authenticator client to be associated with the registration.
         * @param accountName The account name associated with the service.
         * @param httpClient Optional HTTP client instance. Defaults to NetworkHelper.getInstance.
         * @return A [RegistrationInitiation] JSON string representing the registration initiation.
         * @throws MFARegistrationException if the request fails or data cannot be parsed.
         *
         * Example usage:
         * ```kotlin
         * val accountName = "Test Account"
         *
         * // Obtain the JSON payload containing the code and registration endpoint.
         * val initiateUrl = URL("https://tenanturl/v1.0/authenticators/initiation")
         * val result = CloudRegistrationProvider.inAppInitiate(
         *     initiateUri = initiateUrl,
         *     accessToken = "09876zxyt",
         *     clientId = "a8f0043d-acf5-4150-8622-bde8690dce7d",
         *     accountName = accountName
         * )
         *
         * // Create the registration controller
         * val provider = CloudRegistrationProvider(result)
         *
         * // Instantiate the provider
         * provider.initiate(accountName, pushToken = "abc123")
         * ```
         */
        suspend fun inAppInitiate(
            initiateUri: URL,
            accessToken: String,
            clientId: String,
            accountName: String,
            httpClient: HttpClient = NetworkHelper.getInstance
        ): RegistrationInitiation {
            // Construct the request body
            val requestBody = buildJsonObject {
                put("clientId", clientId)
                put("accountName", accountName)
            }

            // Make the HTTP POST request
            val response = httpClient.post {
                url(initiateUri.toString())
                accept(ContentType.Application.Json)
                contentType(ContentType.Application.Json)
                bearerAuth(accessToken)
                setBody(TextContent(requestBody.toString(), ContentType.Application.Json))
            }

            // Check if the response is successful
            if (response.status.isSuccess()) {
                val responseBody = response.bodyAsText()

                if (responseBody.isEmpty()) {
                    throw MFARegistrationException.DataInitializationFailed()
                }

                return responseBody
            } else {
                throw MFARegistrationException.FailedToParse()
            }
        }
    }

    private val log = LoggerFactory.getLogger(javaClass)

    private val decoder = Json {
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    override val canEnrollBiomtric: Boolean
        get() = canEnrollFingerprint || canEnrollFace

    private val canEnrollFingerprint: Boolean
        get() = metaData.availableFactors.any {
            it.type == EnrollableType.FINGERPRINT
        }

    private val canEnrollFace: Boolean
        get() = metaData.availableFactors.any {
            it.type == EnrollableType.FACE
        }

    override val canEnrollUserPresence: Boolean
        get() = metaData.availableFactors.any { it.type == EnrollableType.USER_PRESENCE }

    private var initializationInfo: InitializationInfo
    private var biometricFactor: BiometricFactorInfo? = null
    private var userPresenceFactor: UserPresenceFactorInfo? = null
    private lateinit var tokenInfo: TokenInfo
    private lateinit var metaData: Metadata

    override var pushToken: String = ""
    override var accountName: String = ""
    override val countOfAvailableEnrollments: Int
        get() {
            return metaData.availableFactors.size
        }
    override var authenticationRequired: Boolean = false
    override var invalidatedByBiometricEnrollment: Boolean = false

    init {
        try {
            initializationInfo = decoder.decodeFromString(data)
            accountName = initializationInfo.accountName
        } catch (e: Exception) {
            throw MFARegistrationException.FailedToParse(e)
        }
    }

    @OptIn(InternalSerializationApi::class)
    internal suspend fun initiate(
        accountName: String,
        pushToken: String?,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<CloudRegistrationProviderResultData> {
        log.entering()
        this.accountName = accountName
        this.pushToken = pushToken.orEmpty()

        return try {
            val registrationUrl =
                URL("${initializationInfo.uri}?skipTotpEnrollment=true")

            val response = httpClient.post {
                url(registrationUrl.toString())
                accept(ContentType.Application.Json)
                setBody(
                    TextContent(
                        constructRequestBody("code").toString(),
                        ContentType.Application.Json
                    )
                )
            }

            if (response.status.isSuccess()) {
                response.bodyAsText().let { responseBodyData ->
                    tokenInfo = decoder.decodeFromString(responseBodyData)
                    val cloudRegistration: CloudRegistration =
                        decoder.decodeFromString(responseBodyData)

                    cloudRegistration.metadataResponse.let {
                        metaData = Metadata(
                            id = cloudRegistration.id,
                            registrationUri = it.registrationUri,
                            serviceName = it.serviceName,
                            transactionUri = it.registrationUri.replaceInPath(
                                "registration",
                                "${cloudRegistration.id}/verifications"

                            ),
                            features = it.features,
                            custom = it.custom,
                            theme = it.theme,
                            availableFactors = cloudRegistration.availableFactors
                        )
                    }

                    return@initiate Result.success(
                        CloudRegistrationProviderResultData(
                            tokenInfo,
                            metaData
                        )
                    )
                }
            } else {
                return Result.failure(MFARegistrationException.General(response.bodyAsText()))
            }
        } catch (e: Throwable) {
            Result.failure(e)
        } finally {
            log.exiting()
        }
    }

    override suspend fun enrollBiometric(httpClient: HttpClient) {

        if (canEnrollFingerprint) {
            performSignatureEnrollment(type = EnrollableType.FINGERPRINT, httpClient = httpClient)
        } else if (canEnrollFace) {
            performSignatureEnrollment(type = EnrollableType.FACE, httpClient = httpClient)
        } else {
            throw MFARegistrationException.NoEnrollableFactors(EnrollableType.FINGERPRINT)
        }
    }


    override suspend fun enrollUserPresence(httpClient: HttpClient) {

        if (!canEnrollUserPresence)
            throw MFARegistrationException.NoEnrollableFactors(EnrollableType.USER_PRESENCE)

        performSignatureEnrollment(
            type = EnrollableType.USER_PRESENCE,
            httpClient = httpClient
        )
    }

    private suspend fun performSignatureEnrollment(
        type: EnrollableType,
        httpClient: HttpClient
    ) {

        require(::tokenInfo.isInitialized) { "TokenInfo must be initialized" }
        require(::metaData.isInitialized) { "MetaData must be initialized" }

        val factor =
            metaData.availableFactors.first { it.type == type } as SignatureEnrollableFactor

        if (!factor.enabled)
            throw MFARegistrationException.SignatureMethodNotEnabled(factor.type)

        val algorithm = try {
            HashAlgorithmType.forSigning(factor.algorithm)
        } catch (_: HashAlgorithmException.InvalidHash) {
            throw MFARegistrationException.InvalidAlgorithm(factor.algorithm)
        }

        val keyName = "${metaData.id}.${type.name}"
        val isBiometric = type == EnrollableType.FACE || type == EnrollableType.FINGERPRINT
        
        generateKeys(
            keyName = keyName,
            algorithm = algorithm,
            authenticationRequired = isBiometric && authenticationRequired,
            invalidatedByBiometricEnrollment = isBiometric && invalidatedByBiometricEnrollment,
        ).let { publicKey ->
            sign(
                keyName,
                algorithm,
                metaData.id,
                android.util.Base64.NO_WRAP
            ).let { signedData ->
                enroll(
                    factor,
                    keyName,
                    HashAlgorithmType.fromString(algorithm),
                    publicKey,
                    signedData,
                    httpClient
                )
            }
        }
    }

    @OptIn(InternalSerializationApi::class)
    private suspend fun enroll(
        signatureEnrollableFactor: SignatureEnrollableFactor,
        keyName: String,
        algorithm: HashAlgorithmType,
        publicKey: String,
        signedData: String,
        httpClient: HttpClient
    ) {
        val isBiometric = signatureEnrollableFactor.type == EnrollableType.FACE ||
                         signatureEnrollableFactor.type == EnrollableType.FINGERPRINT

        val requestBody = buildJsonArray {
            addJsonObject {
                put("subType", signatureEnrollableFactor.type.name.lowercase().snakeToCamelCase())
                put("enabled", true)
                put("attributes", buildJsonObject {
                    put("signedData", signedData)
                    put("publicKey", publicKey)
                    put("deviceSecurity", isBiometric)
                    put("algorithm", HashAlgorithmType.toIsvFormat(algorithm))
                    put("additionalData", buildJsonArray {
                        addJsonObject {
                            put("name", "name")
                            put("value", keyName)
                        }
                    })
                })
            }
        }

        val response = httpClient.post {
            url(signatureEnrollableFactor.uri.toString())
            accept(ContentType.Application.Json)
            bearerAuth(tokenInfo.accessToken)
            setBody(TextContent(requestBody.toString(), ContentType.Application.Json))
        }

        if (response.status.isSuccess()) {
            response.bodyAsText().let { responseBodyData ->

                val enrollments = JSONArray(responseBodyData)

                for (i in 0 until enrollments.length()) {
                    (enrollments[i] as JSONObject).let { enrollment ->
                        val subType = enrollment["subType"] as String
                        val type =
                            EnrollableType.valueOf(subType.camelToSnakeCase().uppercase())
                        val id = enrollment["id"] as String
                        val uuid = UUID.fromString(id)

                        when (signatureEnrollableFactor.type) {
                            EnrollableType.FACE, EnrollableType.FINGERPRINT -> {
                                biometricFactor = BiometricFactorInfo(
                                    id = uuid,
                                    keyName = keyName,
                                    algorithm = algorithm
                                )
                            }

                            else -> {
                                userPresenceFactor = UserPresenceFactorInfo(
                                    id = uuid,
                                    keyName = keyName,
                                    algorithm = algorithm
                                )
                            }
                        }
                    }
                }
            }
        } else {
            val errorMessage = try {
                response.bodyAsText()
            } catch (e: Exception) {
                "Enrollment failed with status: ${response.status}"
            }
            throw MFARegistrationException.General(errorMessage)
        }
    }


    @OptIn(InternalSerializationApi::class)
    override suspend fun finalize(httpClient: HttpClient): Result<MFAAuthenticatorDescriptor> {

        return try {

            val registrationUrl =
                URL("${initializationInfo.uri}?metadataInResponse=false")

            // Refresh the token, which sets the authenticator state from ENROLLING to ACTIVE.
            val response = httpClient.post {
                url(registrationUrl.toString())
                accept(ContentType.Application.Json)
                setBody(
                    TextContent(
                        constructRequestBody("refreshToken").toString(),
                        ContentType.Application.Json
                    )
                )
            }

            if (response.status.isSuccess()) {
                response.bodyAsText().let { responseBodyData ->
                    tokenInfo = decoder.decodeFromString(responseBodyData)
                }
                Result.success(
                    CloudAuthenticator(
                        refreshUri = metaData.registrationUri,
                        transactionUri =
                            metaData.registrationUri.replaceInPath(
                                "registration",
                                "${metaData.id}/verifications"
                            ),
                        theme = metaData.theme,
                        token = tokenInfo,
                        id = metaData.id,
                        serviceName = metaData.serviceName,
                        accountName = accountName,
                        biometric = biometricFactor,
                        userPresence = userPresenceFactor,
                        customAttributes = metaData.custom
                    )
                )
            } else {
                Result.failure(
                    MFARegistrationException.General(
                        "Finalization failed with status: ${response.status}"
                    )
                )
            }
        } catch (e: Throwable) {
            Result.failure(
                MFARegistrationException.General(
                    e.localizedMessage ?: "Finalization failed", e
                )
            )
        } finally {
            log.exiting()
        }
    }

    private fun constructRequestBody(additionalData: String): JsonObject {

        val attributes =
            MFAAttributeInfo.init(ContextHelper.context).dictionary().toMutableMap()
        attributes["accountName"] = this.accountName
        attributes["pushToken"] = this.pushToken
        attributes.remove("applicationName")

        val data = mutableMapOf<String, Any>()
        data["attributes"] = attributes.toJsonObject()

        when (additionalData) {
            "refreshToken" -> data["refreshToken"] = tokenInfo.refreshToken
            "code" -> data["code"] = initializationInfo.code
        }

        return data.toJsonObject()
    }
}