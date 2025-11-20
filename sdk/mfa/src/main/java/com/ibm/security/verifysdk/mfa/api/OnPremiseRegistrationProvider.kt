/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import com.ibm.security.verifysdk.authentication.api.OAuthProvider
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.extension.entering
import com.ibm.security.verifysdk.core.extension.exiting
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.mfa.EnrollableSignature
import com.ibm.security.verifysdk.mfa.EnrollableType
import com.ibm.security.verifysdk.mfa.FactorType
import com.ibm.security.verifysdk.mfa.FingerprintFactorInfo
import com.ibm.security.verifysdk.mfa.HashAlgorithmType
import com.ibm.security.verifysdk.mfa.MFAAttributeInfo
import com.ibm.security.verifysdk.mfa.MFAAuthenticatorDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationError
import com.ibm.security.verifysdk.mfa.SignatureEnrollableFactor
import com.ibm.security.verifysdk.mfa.TOTPFactorInfo
import com.ibm.security.verifysdk.mfa.UserPresenceFactorInfo
import com.ibm.security.verifysdk.mfa.generateKeys
import com.ibm.security.verifysdk.mfa.model.onprem.DetailsData
import com.ibm.security.verifysdk.mfa.model.onprem.EnrollmentResult
import com.ibm.security.verifysdk.mfa.model.onprem.InitializationInfo
import com.ibm.security.verifysdk.mfa.model.onprem.Metadata
import com.ibm.security.verifysdk.mfa.model.onprem.OnPremiseAuthenticator
import com.ibm.security.verifysdk.mfa.model.onprem.OnPremiseRegistrationProviderResultData
import com.ibm.security.verifysdk.mfa.model.onprem.OnPremiseTOTPEnrollableFactor
import com.ibm.security.verifysdk.mfa.model.onprem.TotpConfiguration
import com.ibm.security.verifysdk.mfa.sign
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.get
import io.ktor.client.request.patch
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory
import java.net.URL
import java.util.UUID

class OnPremiseRegistrationProvider(data: String) :
    MFARegistrationDescriptor<MFAAuthenticatorDescriptor> {

    private val log = LoggerFactory.getLogger(javaClass)

    private val decoder =  Json {
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    private val initializationInfo: InitializationInfo
    private lateinit var tokenInfo: TokenInfo
    private lateinit var metaData: Metadata
    private lateinit var authenticatorId: String

    private var currentFactor: SignatureEnrollableFactor? = null
    @OptIn(InternalSerializationApi::class)
    private var factors: MutableList<FactorType> = mutableListOf()


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
        } catch (e: Exception) {
            throw MFARegistrationError.FailedToParse
        }
    }

    @OptIn(InternalSerializationApi::class)
    internal suspend fun initiate(
        accountName: String,
        skipTotpEnrollment: Boolean = true,
        pushToken: String?,
        additionalHeaders: HashMap<String, String>?,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<OnPremiseRegistrationProviderResultData> {

        return try {
            log.entering()
            this.accountName = accountName
            this.pushToken = pushToken.orEmpty()
            val responseDetail = httpClient.get {
                url(initializationInfo.uri)
            }

            if (responseDetail.status.isSuccess()) {
                responseDetail.bodyAsText().let { responseBodyData ->
                    val detailsData: DetailsData = decoder.decodeFromString(responseBodyData)
                    detailsData.let {
                        metaData = Metadata(
                            registrationUri = detailsData.tokenEndpoint,
                            transactionUri = detailsData.authntrxnEndpoint,
                            signatureUri = detailsData.enrollmentEndpoint,
                            totpUri = detailsData.totpSharedSecretEndpoint,
                            qrloginUri = detailsData.qrloginEndpoint,
                            serviceName = detailsData.serviceName,
                            availableFactors = detailsData.availableFactors,
                            theme = detailsData.theme ?: hashMapOf(),
                            features = arrayListOf()
                        )
                    }
                }
            } else {
                return Result.failure(
                    MFARegistrationError.UnderlyingError(
                        Error(
                            responseDetail.bodyAsText()
                        )
                    )
                )
            }

            val attributes =
                MFAAttributeInfo.init(ContextHelper.context).dictionary(snakeCaseKey = true)
                    .toMutableMap()
            attributes["accountName"] = this.accountName
            attributes["pushToken"] = this.pushToken
            attributes["tenant_id"] = UUID.randomUUID().toString()

            val oAuthProvider = OAuthProvider(
                clientId = initializationInfo.clientId,
                additionalHeaders = additionalHeaders,
                additionalParameters = attributes.toMap()
                    .mapValues { entry -> entry.value.toString() }
                    .toMutableMap()
            )
            if (initializationInfo.ignoreSSLCertificate) {
                // disable SSL validations for network client
            }

            val responseToken = oAuthProvider.authorize(
                url = metaData.registrationUri,
                authorizationCode = initializationInfo.code,
                scope = arrayOf("mmfaAuthn"),
                httpClient = httpClient
            )

            responseToken.fold(
                onSuccess = { tokenInfo ->
                    this.tokenInfo = tokenInfo
                    authenticatorId = tokenInfo.additionalData["authenticator_id"] as? String
                        ?: return Result.failure(MFARegistrationError.MissingAuthenticatorIdentifier)

                    if (countOfAvailableEnrollments == 0) {
                        return Result.failure(MFARegistrationError.NoEnrollableFactors)
                    }

                    val totpFactor =
                        metaData.availableFactors.find { factor -> factor.type == EnrollableType.TOTP }

                    totpFactor?.let { factor ->
                        (factor as? OnPremiseTOTPEnrollableFactor)?.let { onPremiseTotpEnrollableFactor ->
                            if (skipTotpEnrollment.not()) {

                                val responseTotp = httpClient.get {
                                    url(onPremiseTotpEnrollableFactor.uri)
                                    accept(ContentType.Application.Json)
                                    bearerAuth(tokenInfo.accessToken)
                                }

                                if (responseTotp.status.isSuccess()) {
                                    responseTotp.bodyAsText().let { responseTotpData ->
                                        val totp: TotpConfiguration =
                                            decoder.decodeFromString(responseTotpData)
                                        totp.let { totpRegistration ->
                                            factors.add(
                                                FactorType.Totp(
                                                    TOTPFactorInfo(
                                                        secret = totpRegistration.secretKey,
                                                        algorithm = HashAlgorithmType.fromString(
                                                            totpRegistration.algorithm
                                                        ),
                                                        digits = totpRegistration.digits.toInt(),
                                                        period = totpRegistration.period.toInt()
                                                    )
                                                )
                                            )
                                        }
                                    }
                                } else {
                                    return Result.failure(MFARegistrationError.EnrollmentFailed)
                                }
                            }
                            metaData.availableFactors.removeAll { factor -> factor.type == EnrollableType.TOTP }
                        }
                    }

                    return Result.success(
                        OnPremiseRegistrationProviderResultData(
                            tokenInfo,
                            metaData
                        )
                    )
                },
                onFailure = {
                    return Result.failure(MFARegistrationError.FailedToParse)
                }
            )
        } catch (e: Throwable) {
            Result.failure(e)
        } finally {
            log.exiting()
        }
    }


    override fun nextEnrollment(): EnrollableSignature? {

        return try {
            log.entering()

            require(::tokenInfo.isInitialized) { "TokenInfo must be initialized" }
            require(::metaData.isInitialized) { "MetaData must be initialized" }
            require(::authenticatorId.isInitialized) { "Authenticator ID must be initialized" }

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
                                authenticatorId,
                                signatureEnrollableFactor.type
                            )
                        }
                    }
                }
            }
        } finally {
            require(currentFactor != null) { "currentFactor must not be null" }
            log.exiting()
        }
    }

    override suspend fun enroll(httpClient: HttpClient) {

        try {
            log.entering()

            require(::tokenInfo.isInitialized) { "TokenInfo must be initialized" }
            require(::metaData.isInitialized) { "MetaData must be initialized" }
            require(::authenticatorId.isInitialized) { "Authenticator ID must be initialized" }
            require(currentFactor != null) { "currentFactor must not be null" }

            currentFactor?.let { signatureEnrollableFactor ->
                val keyName = "${authenticatorId}.${signatureEnrollableFactor.type.name}"
                log.debug("Key generated: $keyName")
                generateKeys(
                    keyName,
                    HashAlgorithmType.forSigning(signatureEnrollableFactor.algorithm)
                ).let { publicKey ->
                    sign(
                        keyName,
                        HashAlgorithmType.forSigning(signatureEnrollableFactor.algorithm),
                        authenticatorId,
                        android.util.Base64.NO_WRAP
                    ).let { signedData ->
                        enroll(keyName, publicKey, signedData, httpClient = httpClient)
                    }
                }
            }
        } finally {
            log.exiting()
        }
    }


    @OptIn(InternalSerializationApi::class)
    override suspend fun enroll(keyName: String, publicKey: String, signedData: String, httpClient: HttpClient) {

        try {
            log.entering()

            require(::tokenInfo.isInitialized) { "TokenInfo must be initialized" }
            require(::metaData.isInitialized) { "MetaData must be initialized" }
            require(::authenticatorId.isInitialized) { "Authenticator ID must be initialized" }
            require(currentFactor != null) { "currentFactor must not be null" }

            val algorithm = HashAlgorithmType.fromString(currentFactor?.algorithm ?: "")
            val path =
                "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:${
                    EnrollableType.forIsvaEnrollment(
                        currentFactor?.type
                    )
                }Methods"
            val enrollmentUrl = URL("${currentFactor?.uri}?attributes=${path}")

            val requestBody = buildJsonObject {
                put(
                    "schemas",
                    buildJsonArray { add("urn:ietf:params:scim:api:messages:2.0:PatchOp") })
                put("Operations", buildJsonArray {
                    addJsonObject {
                        put("op", "add")
                        put("path", path)
                        put("value", buildJsonArray {
                            addJsonObject {
                                put("enabled", true)
                                put("keyHandle", keyName)
                                put(
                                    "algorithm",
                                    HashAlgorithmType.forSigning(currentFactor?.algorithm ?: "")
                                )
                                put("publicKey", publicKey)
                            }
                        })
                    }
                })
            }

            val response = httpClient.patch {
                url(enrollmentUrl)
                accept(ContentType.Application.Json)
                contentType(ContentType.Application.Json)
                bearerAuth(tokenInfo.accessToken)
                setBody(requestBody)
            }

            if (response.status.isSuccess()) {
                response.bodyAsText().let { responseBodyData ->
                    val enrrollmentResult =
                        decoder.decodeFromString<EnrollmentResult>(responseBodyData)

                    when (currentFactor?.type) {
                        EnrollableType.FINGERPRINT -> factors.add(
                            FactorType.Fingerprint(
                                FingerprintFactorInfo(
                                    id = UUID.fromString(
                                        enrrollmentResult.resources[0].authenticator.fingerprintMethods?.get(
                                            0
                                        )?.id?.replace(
                                            "uuid",
                                            ""
                                        ) // ISVA adds a "uuid" prefix to the value
                                    ),
                                    keyName = keyName,
                                    algorithm = algorithm
                                )
                            )
                        )

                        else -> factors.add(
                            FactorType.UserPresence(
                                UserPresenceFactorInfo(
                                    id = UUID.fromString(
                                        enrrollmentResult.resources[0].authenticator.userPresenceMethods?.get(
                                            0
                                        )?.id?.replace(
                                            "uuid",
                                            ""
                                        ) // ISVA adds a "uuid" prefix to the value
                                    ),
                                    keyName = keyName,
                                    algorithm = algorithm
                                )
                            )
                        )
                    }
                }
            } else {
                throw MFARegistrationError.DataInitializationFailed
            }
        } finally {
            log.exiting()
        }
    }

    @OptIn(InternalSerializationApi::class)
    override suspend fun finalize(httpClient: HttpClient): Result<MFAAuthenticatorDescriptor> {
        return try {
            log.entering()

            Result.success(
                OnPremiseAuthenticator(
                    refreshUri = URL(metaData.registrationUri.toString()),
                    transactionUri = URL(metaData.transactionUri.toString()),
                    theme = metaData.theme,
                    token = tokenInfo,
                    id = authenticatorId,
                    serviceName = metaData.serviceName,
                    accountName = accountName,
                    allowedFactors = factors,
                    qrLoginUri = URL(metaData.qrloginUri.toString()),
                    ignoreSSLCertificate = initializationInfo.ignoreSSLCertificate,
                    clientId = initializationInfo.clientId
                )
            )
        } catch (e: Throwable) {
            Result.failure(e)
        } finally {
            log.exiting()
        }
    }
}