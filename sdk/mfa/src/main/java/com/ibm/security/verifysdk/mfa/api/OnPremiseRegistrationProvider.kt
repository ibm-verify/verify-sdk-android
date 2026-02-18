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
import com.ibm.security.verifysdk.mfa.BiometricFactorInfo
import com.ibm.security.verifysdk.mfa.EnrollableSignature
import com.ibm.security.verifysdk.mfa.EnrollableType
import com.ibm.security.verifysdk.mfa.HashAlgorithmException
import com.ibm.security.verifysdk.mfa.HashAlgorithmType
import com.ibm.security.verifysdk.mfa.MFAAttributeInfo
import com.ibm.security.verifysdk.mfa.MFAAuthenticatorDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationException
import com.ibm.security.verifysdk.mfa.SignatureEnrollableFactor
import com.ibm.security.verifysdk.mfa.UserPresenceFactorInfo
import com.ibm.security.verifysdk.mfa.generateKeys
import com.ibm.security.verifysdk.mfa.model.onprem.DetailsData
import com.ibm.security.verifysdk.mfa.model.onprem.EnrollmentResult
import com.ibm.security.verifysdk.mfa.model.onprem.InitializationInfo
import com.ibm.security.verifysdk.mfa.model.onprem.Metadata
import com.ibm.security.verifysdk.mfa.model.onprem.OnPremiseAuthenticator
import com.ibm.security.verifysdk.mfa.model.onprem.OnPremiseRegistrationProviderResultData
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
import io.ktor.http.content.TextContent
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

    private val initializationInfo: InitializationInfo
    private var biometricFactor: BiometricFactorInfo? = null
    private var userPresenceFactor: UserPresenceFactorInfo? = null
    private lateinit var tokenInfo: TokenInfo
    private lateinit var metaData: Metadata
    private lateinit var authenticatorId: String

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
            throw MFARegistrationException.FailedToParse(e)
        }
    }

    @OptIn(InternalSerializationApi::class)
    internal suspend fun initiate(
        accountName: String,
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
                    MFARegistrationException.General(responseDetail.bodyAsText())
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
                        ?: return Result.failure(MFARegistrationException.MissingAuthenticatorIdentifier())

                    if (countOfAvailableEnrollments == 0) {
                        return Result.failure(MFARegistrationException.NoEnrollableFactors())
                    }

                    return Result.success(
                        OnPremiseRegistrationProviderResultData(
                            tokenInfo,
                            metaData
                        )
                    )
                },
                onFailure = { e ->
                    return Result.failure(MFARegistrationException.FailedToParse(e))
                }
            )
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
        require(::authenticatorId.isInitialized) { "Authenticator ID must be initialized" }

        val factor =
            metaData.availableFactors.first { it.type == type } as SignatureEnrollableFactor

        if (!factor.enabled)
            throw MFARegistrationException.SignatureMethodNotEnabled(factor.type)

        try {
            HashAlgorithmType.forSigning(factor.algorithm)
        } catch (_: HashAlgorithmException.InvalidHash) {
            throw MFARegistrationException.InvalidAlgorithm(factor.algorithm)
        }

        val keyName = "${authenticatorId}.${type.name}"
        val algorithm =
            HashAlgorithmType.forSigning((metaData.availableFactors.first { it.type == type } as SignatureEnrollableFactor).algorithm)
        generateKeys(
            keyName = keyName,
            algorithm = algorithm,
            authenticationRequired = (type == EnrollableType.FACE || type == EnrollableType.FINGERPRINT) && authenticationRequired,
            invalidatedByBiometricEnrollment = (type == EnrollableType.FACE || type == EnrollableType.FINGERPRINT) && authenticationRequired,
        ).let { publicKey ->
            enroll(
                type,
                factor,
                keyName,
                HashAlgorithmType.fromString(algorithm),
                publicKey,
                httpClient
            )
        }
    }


    @OptIn(InternalSerializationApi::class)
    private suspend fun enroll(
        type: EnrollableType,
        signatureEnrollableFactor: SignatureEnrollableFactor,
        keyName: String,
        algorithm: HashAlgorithmType,
        publicKey: String,
        httpClient: HttpClient
    ) {

        try {
            log.entering()

            val path =
                "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:${
                    EnrollableType.forIsvaEnrollment(type)
                }Methods"
            val enrollmentUrl = URL("${signatureEnrollableFactor.uri}?attributes=${path}")

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
                                    HashAlgorithmType.forSigning(algorithm.toString())
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
                bearerAuth(tokenInfo.accessToken)
                setBody(TextContent(requestBody.toString(), ContentType.Application.Json))
            }

            if (response.status.isSuccess()) {
                response.bodyAsText().let { responseBodyData ->
                    val enrollmentResult =
                        decoder.decodeFromString<EnrollmentResult>(responseBodyData)

                    when (signatureEnrollableFactor.type) {
                        EnrollableType.FINGERPRINT, EnrollableType.FACE -> {
                            biometricFactor = BiometricFactorInfo(
                                id = UUID.fromString(
                                    enrollmentResult.resources[0].authenticator.fingerprintMethods?.get(
                                        0
                                    )?.id?.replace(
                                        "uuid",
                                        ""
                                    ) // IBM Verify Access adds an "uuid" prefix to the value
                                ),
                                keyName = keyName,
                                algorithm = algorithm
                            )
                        }

                        EnrollableType.USER_PRESENCE -> {
                            userPresenceFactor = UserPresenceFactorInfo(
                                id = UUID.fromString(
                                    enrollmentResult.resources[0].authenticator.userPresenceMethods?.get(
                                        0
                                    )?.id?.replace(
                                        "uuid",
                                        ""
                                    ) // IBM Verify Access adds an "uuid" prefix to the value
                                ),
                                keyName = keyName,
                                algorithm = algorithm
                            )
                        }

                        EnrollableType.TOTP , EnrollableType.HOTP -> {

                        }
                    }
                }
            } else {
                throw MFARegistrationException.DataInitializationFailed()
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
                    userPresence = userPresenceFactor,
                    biometric = biometricFactor,
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