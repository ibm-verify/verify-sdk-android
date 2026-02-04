/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.extension.camelToSnakeCase
import com.ibm.security.verifysdk.core.extension.entering
import com.ibm.security.verifysdk.core.extension.exiting
import com.ibm.security.verifysdk.core.extension.replace
import com.ibm.security.verifysdk.core.extension.snakeToCamelCase
import com.ibm.security.verifysdk.core.extension.toJsonObject
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.mfa.EnrollableSignature
import com.ibm.security.verifysdk.mfa.EnrollableType
import com.ibm.security.verifysdk.mfa.FaceFactorInfo
import com.ibm.security.verifysdk.mfa.FactorType
import com.ibm.security.verifysdk.mfa.FingerprintFactorInfo
import com.ibm.security.verifysdk.mfa.HashAlgorithmType
import com.ibm.security.verifysdk.mfa.MFAAttributeInfo
import com.ibm.security.verifysdk.mfa.MFAAuthenticatorDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationError
import com.ibm.security.verifysdk.mfa.RegistrationInitiation
import com.ibm.security.verifysdk.mfa.SignatureEnrollableFactor
import com.ibm.security.verifysdk.mfa.TOTPFactorInfo
import com.ibm.security.verifysdk.mfa.UserPresenceFactorInfo
import com.ibm.security.verifysdk.mfa.generateKeys
import com.ibm.security.verifysdk.mfa.model.cloud.CloudAuthenticator
import com.ibm.security.verifysdk.mfa.model.cloud.CloudRegistration
import com.ibm.security.verifysdk.mfa.model.cloud.CloudRegistrationProviderResultData
import com.ibm.security.verifysdk.mfa.model.cloud.CloudTOTPEnrollableFactor
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
         * @throws Exception if the request fails or data cannot be parsed.
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
                    throw MFARegistrationError.DataInitializationFailed
                }
                
                return responseBody
            } else {
                throw MFARegistrationError.FailedToParse
            }
        }
    }

    private val log = LoggerFactory.getLogger(javaClass)

    private val decoder =  Json {
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    private var initializationInfo: InitializationInfo
    private var currentFactor: SignatureEnrollableFactor? = null
    @OptIn(InternalSerializationApi::class)
    private var factors: MutableList<FactorType> = mutableListOf()
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
            throw MFARegistrationError.FailedToParse
        }
    }

    @OptIn(InternalSerializationApi::class)
    internal suspend fun initiate(
        accountName: String,
        skipTotpEnrollment: Boolean = true,
        pushToken: String?,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<CloudRegistrationProviderResultData> {
        log.entering()
        this.accountName = accountName
        this.pushToken = pushToken.orEmpty()

        return try {
            val registrationUrl =
                URL("${initializationInfo.uri}?skipTotpEnrollment=${skipTotpEnrollment}")

            val response = httpClient.post {
                url(registrationUrl.toString())
                accept(ContentType.Application.Json)
                setBody(TextContent(constructRequestBody("code").toString(), ContentType.Application.Json))
            }

            if (response.status.isSuccess()) {
                response.bodyAsText().let { responseBodyData ->
                    tokenInfo = decoder.decodeFromString(responseBodyData)
                    val cloudRegistration: CloudRegistration = decoder.decodeFromString(responseBodyData)

                    cloudRegistration.metadataContainer.let {
                        metaData = Metadata(
                            id = cloudRegistration.id,
                            registrationUri = it.registrationUri,
                            serviceName = it.serviceName,
                            transactionUri = it.registrationUri.replace(
                                "registration",
                                "${cloudRegistration.id}/verifications"
                            ),
                            features = it.features,
                            custom = it.custom,
                            theme = it.theme,
                            availableFactors = cloudRegistration.availableFactors
                        )
                    }

                    cloudRegistration.availableFactors.stream()
                        .filter { factor -> factor.type == EnrollableType.TOTP }.findFirst()
                        .ifPresent { factor ->
                            (factor as? CloudTOTPEnrollableFactor)?.let { cloudTotpEnrollableFactor ->
                                if (skipTotpEnrollment.not()) {
                                    factors.add(
                                        FactorType.Totp(
                                            TOTPFactorInfo(
                                                secret = cloudTotpEnrollableFactor.secret,
                                                algorithm = HashAlgorithmType.fromString(
                                                    cloudTotpEnrollableFactor.algorithm
                                                ),
                                                digits = cloudTotpEnrollableFactor.digits,
                                                period = cloudTotpEnrollableFactor.period
                                            )
                                        )
                                    )
                                }
                            }
                        }
                    cloudRegistration.availableFactors.removeAll { factor -> factor.type == EnrollableType.TOTP }

                    return@initiate Result.success(
                        CloudRegistrationProviderResultData(
                            tokenInfo,
                            metaData
                        )
                    )
                }
            } else {
                return Result.failure(MFARegistrationError.UnderlyingError(Error(response.bodyAsText())))
            }
        } catch (e: Throwable) {
            Result.failure(e)
        } finally {
            log.exiting()
        }
    }

    override fun nextEnrollment(): EnrollableSignature? {

        return try {
            log.entering()

            if (metaData.availableFactors.isEmpty()) {
                null
            } else {
                metaData.availableFactors.first().let { enrollableFactor ->
                    (enrollableFactor as SignatureEnrollableFactor).let { signatureEnrollableFactor ->
                        currentFactor = signatureEnrollableFactor
                        metaData.availableFactors.removeAll { enrollableFactor.type == it.type }

                        val algorithm =
                            currentFactor?.algorithm?.let { HashAlgorithmType.fromString(it) }
                        val biometricAuthentication =
                            (currentFactor?.type == EnrollableType.USER_PRESENCE).not()

                        algorithm?.let {
                            EnrollableSignature(
                                biometricAuthentication,
                                it,
                                metaData.id,
                                signatureEnrollableFactor.type
                            )
                        }
                    }
                }
            }
        } finally {
            log.exiting()
        }
    }

    override suspend fun enroll(httpClient: HttpClient) {

        currentFactor?.let { signatureEnrollableFactor ->
            val keyName = "${metaData.id}.${signatureEnrollableFactor.type.name}"
            generateKeys(
                keyName,
                HashAlgorithmType.forSigning(signatureEnrollableFactor.algorithm)
            ).let { publicKey ->
                sign(
                    keyName,
                    HashAlgorithmType.forSigning(signatureEnrollableFactor.algorithm),
                    metaData.id,
                    android.util.Base64.NO_WRAP
                ).let { signedData ->
                    enroll(keyName, publicKey, signedData, httpClient)
                }
            }
        }
    }

    @OptIn(InternalSerializationApi::class)
    override suspend fun enroll(keyName: String, publicKey: String, signedData: String, httpClient: HttpClient) {

        val algorithm = HashAlgorithmType.fromString(currentFactor?.algorithm ?: "")

        val requestBody = buildJsonArray {
            addJsonObject {
                put("subType", currentFactor?.type?.name?.lowercase()?.snakeToCamelCase())
                put("enabled", true)
                put("attributes", buildJsonObject {
                    put("signedData", signedData)
                    put("publicKey", publicKey)
                    put(
                        "deviceSecurity",
                        currentFactor?.type == EnrollableType.FACE || currentFactor?.type == EnrollableType.FINGERPRINT
                    )
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
            url(currentFactor?.uri.toString())
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

                        if (type == currentFactor?.type) {
                            when (currentFactor?.type) {
                                EnrollableType.FACE -> factors.add(
                                    FactorType.Face(
                                        FaceFactorInfo(
                                            id = uuid,
                                            keyName = keyName,
                                            algorithm = algorithm
                                        )
                                    )
                                )

                                EnrollableType.FINGERPRINT -> factors.add(
                                    FactorType.Fingerprint(
                                        FingerprintFactorInfo(
                                            id = uuid,
                                            keyName = keyName,
                                            algorithm = algorithm
                                        )
                                    )
                                )

                                else -> factors.add(
                                    FactorType.UserPresence(
                                        UserPresenceFactorInfo(
                                            id = uuid,
                                            keyName = keyName,
                                            algorithm = algorithm
                                        )
                                    )
                                )
                            }
                        }
                    }
                }
            }
        } else {
            throw MFARegistrationError.UnderlyingError(Error(response.bodyAsText()))
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
                setBody(TextContent(constructRequestBody("refreshToken").toString(), ContentType.Application.Json))
            }

            if (response.status.isSuccess()) {
                response.bodyAsText().let { responseBodyData ->
                    tokenInfo = decoder.decodeFromString(responseBodyData)
                }
            }
            Result.success(
                CloudAuthenticator(
                    refreshUri = metaData.registrationUri,
                    transactionUri = metaData.registrationUri.replace(
                        "registration",
                        "${metaData.id}/verifications"
                    ),
                    theme = metaData.theme,
                    token = tokenInfo,
                    id = metaData.id,
                    serviceName = metaData.serviceName,
                    accountName = accountName,
                    allowedFactors = factors,
                    customAttributes = metaData.custom
                )
            )
        } catch (e: Throwable) {
            Result.failure(e)
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