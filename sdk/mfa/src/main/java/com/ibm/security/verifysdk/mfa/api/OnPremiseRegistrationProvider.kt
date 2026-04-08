/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.biometric.BiometricPrompt
import com.ibm.security.verifysdk.authentication.api.OAuthProvider
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.extension.entering
import com.ibm.security.verifysdk.core.extension.exiting
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.core.helper.KeystoreHelper
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
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.get
import io.ktor.client.request.patch
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.content.TextContent
import io.ktor.http.contentType
import io.ktor.http.formUrlEncode
import io.ktor.http.headers
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

    override val canEnrollBiometric: Boolean
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

    /**
     * Holds the pending biometric enrollment state when [authenticationRequired] is `true`.
     * Set by [getCryptoObjectForEnrollment] and consumed by [enrollBiometric(BiometricPrompt.CryptoObject)].
     *
     * Marked [@Volatile] so that writes from one thread are immediately visible to reads on another.
     */
    @Volatile
    private var pendingBiometricEnrollment: PendingBiometricEnrollment? = null

    /** Captures the key name, algorithm and factor needed to complete enrollment after biometric auth. */
    private data class PendingBiometricEnrollment(
        val type: EnrollableType,
        val factor: SignatureEnrollableFactor,
        val keyName: String,
        val algorithm: String,
        val publicKey: String
    )

    override var pushToken: String = ""
    override val serviceName: String
        get() = if (::metaData.isInitialized) metaData.serviceName else ""
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
                MFAAttributeInfo.dictionary(snakeCaseKey = true).toMutableMap()
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

    /**
     * Generates the biometric key pair and returns a [BiometricPrompt.CryptoObject] that must
     * be passed to [BiometricPrompt.authenticate] when [authenticationRequired] is `true`.
     *
     * This method is SDK-internal.  Callers should call [enrollBiometric] and catch
     * [MFARegistrationException.BiometricAuthenticationRequired] to obtain the
     * [BiometricPrompt.CryptoObject].
     *
     * Returns `null` when [authenticationRequired] is `false` or no biometric factor is available.
     */
    internal fun getCryptoObjectForEnrollment(): BiometricPrompt.CryptoObject? {

        require(::metaData.isInitialized) { "MetaData must be initialized. Call initiate() first." }
        require(::authenticatorId.isInitialized) { "Authenticator ID must be initialized. Call initiate() first." }

        val type = when {
            canEnrollFingerprint -> EnrollableType.FINGERPRINT
            canEnrollFace -> EnrollableType.FACE
            else -> return null
        }

        if (!authenticationRequired) return null

        val factor = metaData.availableFactors.first { it.type == type } as SignatureEnrollableFactor

        if (!factor.enabled) throw MFARegistrationException.SignatureMethodNotEnabled(factor.type)

        val algorithm = try {
            HashAlgorithmType.forSigning(factor.algorithm)
        } catch (_: HashAlgorithmException.InvalidHash) {
            throw MFARegistrationException.InvalidAlgorithm(factor.algorithm)
        }

        val keyName = "${authenticatorId}.${type.name}"

        // Generate the key pair with authenticationRequired = true.
        val publicKey = generateKeys(
            keyName = keyName,
            algorithm = algorithm,
            authenticationRequired = true,
            invalidatedByBiometricEnrollment = invalidatedByBiometricEnrollment,
        )

        // Store the pending enrollment state so enrollBiometric(cryptoObject) can complete it.
        pendingBiometricEnrollment = PendingBiometricEnrollment(
            type = type,
            factor = factor,
            keyName = keyName,
            algorithm = algorithm,
            publicKey = publicKey
        )

        // Return a CryptoObject wrapping the Signature pre-initialised with the locked key.
        return KeystoreHelper.getCryptoObject(keyName, algorithm)
    }

    /**
     * Completes biometric enrollment using a hardware-unlocked [BiometricPrompt.CryptoObject]
     * returned from [BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded].
     *
     * Must be called after [getCryptoObjectForEnrollment] and a successful biometric
     * authentication.  The [cryptoObject] carries the authenticated [java.security.Signature]
     * that signs the enrollment challenge without exposing the raw private key.
     *
     * @throws MFARegistrationException.InvalidPendingEnrollment if [getCryptoObjectForEnrollment]
     *         was not called first.
     */
    override suspend fun enrollBiometric(
        cryptoObject: BiometricPrompt.CryptoObject,
        httpClient: HttpClient
    ) {
        val pending = pendingBiometricEnrollment
            ?: throw MFARegistrationException.InvalidPendingEnrollment()

        pendingBiometricEnrollment = null

        // On-premise enrollment uses a SCIM PATCH with publicKey + keyHandle only.
        // The CryptoObject has already unlocked the key via biometric authentication;
        // no separate signedData field is required in the request body.
        enroll(
            pending.type,
            pending.factor,
            pending.keyName,
            HashAlgorithmType.fromString(pending.algorithm),
            pending.publicKey,
            httpClient
        )
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

        // OPT-3: resolve algorithm once and reuse — avoids a redundant list scan.
        val algorithm = try {
            HashAlgorithmType.forSigning(factor.algorithm)
        } catch (_: HashAlgorithmException.InvalidHash) {
            throw MFARegistrationException.InvalidAlgorithm(factor.algorithm)
        }

        val keyName = "${authenticatorId}.${type.name}"
        val isBiometric = type == EnrollableType.FACE || type == EnrollableType.FINGERPRINT

        // OPT-1: When authenticationRequired is true for a biometric key, the key is locked after
        // generation and cannot be signed without a BiometricPrompt.CryptoObject.
        // getCryptoObjectForEnrollment() generates the key, stores the pending state, and
        // returns a CryptoObject.  We throw BiometricAuthenticationRequired so the caller
        // can show the BiometricPrompt and then call enrollBiometric(cryptoObject).
        if (isBiometric && authenticationRequired) {
            val cryptoObject = getCryptoObjectForEnrollment()
                ?: throw MFARegistrationException.NoEnrollableFactors(type)
            throw MFARegistrationException.BiometricAuthenticationRequired(cryptoObject)
        }

        // OPT-2: use the interface property invalidatedByBiometricEnrollment (not authenticationRequired).
        val publicKey = generateKeys(
            keyName = keyName,
            algorithm = algorithm,
            authenticationRequired = false,
            invalidatedByBiometricEnrollment = isBiometric && invalidatedByBiometricEnrollment,
        )

        enroll(
            type,
            factor,
            keyName,
            HashAlgorithmType.fromString(algorithm),
            publicKey,
            httpClient
        )
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

            // Generate requestBody for token refresh based on OnPremiseAuthenticatorService.refreshToken
            val attributes = MFAAttributeInfo.dictionary(snakeCaseKey = true).toMutableMap()
            attributes["accountName"] = accountName
            attributes["pushToken"] = pushToken
            attributes["tenant_id"] = authenticatorId

            val requestBody = mutableMapOf(
                "grant_type" to "refresh_token",
                "client_id" to initializationInfo.clientId,
                "refresh_token" to tokenInfo.refreshToken
            )
            
            attributes.forEach { (key, value) ->
                requestBody[key] = value.toString()
            }

            val response = httpClient.post {
                url(metaData.registrationUri.toString())
                accept(ContentType.Application.Json)
                contentType(ContentType.Application.FormUrlEncoded)
                setBody(requestBody.toList().formUrlEncode())
            }

            if (response.status.isSuccess()) {
                response.bodyAsText().let { responseBodyData ->
                    tokenInfo = decoder.decodeFromString(responseBodyData)
                }
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
}