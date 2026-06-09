/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.biometric.BiometricPrompt
import com.ibm.security.verifysdk.authentication.api.OAuthProvider
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.extension.entering
import com.ibm.security.verifysdk.core.extension.exiting
import com.ibm.security.verifysdk.core.helper.KeystoreHelper
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.mfa.BiometricFactorInfo
import com.ibm.security.verifysdk.mfa.EnrollableType
import com.ibm.security.verifysdk.mfa.HashAlgorithmException
import com.ibm.security.verifysdk.mfa.HashAlgorithmType
import com.ibm.security.verifysdk.mfa.MFAAttributeInfo
import com.ibm.security.verifysdk.mfa.MFAAuthenticatorDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationDescriptor
import com.ibm.security.verifysdk.mfa.MFARegistrationException
import com.ibm.security.verifysdk.mfa.OTPAuthenticator
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
import io.ktor.http.content.TextContent
import io.ktor.http.contentType
import io.ktor.http.formUrlEncode
import io.ktor.http.isSuccess
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.slf4j.LoggerFactory
import java.net.URL
import java.util.UUID

/**
 * Registration provider for IBM Verify Access (on-premise) multifactor authentication.
 *
 * This provider handles the registration flow for on-premise authenticators, including
 * enrollment of biometric, user presence, and TOTP factors.
 *
 * ## SSL Certificate Bypass
 *
 * On-premise deployments may use self-signed certificates or certificates from private CAs.
 * The QR code can include an `ignoreSSLCertificate` flag to indicate that SSL certificate
 * validation should be bypassed for this specific authenticator.
 *
 * ### Two-Level Security Model
 *
 * SSL bypass requires **both** conditions to be met:
 * 1. **QR Code Level**: `ignoreSSLCertificate=true` in the initialization data (indicates need)
 * 2. **App Level**: [NetworkHelper.allowInsecureSSL] = `true` (grants permission)
 *
 * If the QR code requests SSL bypass but the app hasn't enabled it, [initiate] will throw
 * an exception. This prevents accidental SSL bypass and gives the app control over security policy.
 *
 * ## HTTP Client Affinity
 *
 * **Important**: The HTTP client is bound during [initiate] based on the `ignoreSSLCertificate`
 * flag. This client is stored internally and reused for all subsequent registration operations
 * ([enrollBiometric], [enrollUserPresence], [enrollOneTimePasscode], [finalize]).
 *
 * All enrollment methods accept an optional `httpClient` parameter for API compatibility and
 * testing flexibility, but **the parameter is ignored in favor of the stored client** to ensure
 * SSL bypass settings are preserved throughout the registration flow.
 *
 * ### Usage Pattern
 *
 * ```kotlin
 * // 1. Enable SSL bypass at app level (if needed)
 * NetworkHelper.allowInsecureSSL = true
 *
 * // 2. Create provider from QR code
 * val provider = OnPremiseRegistrationProvider(qrData)
 *
 * // 3. Initiate - creates appropriate HTTP client
 * provider.initiate(accountName, pushToken).onSuccess {
 *     // 4. Enroll factors - automatically uses correct client
 *     provider.enrollBiometric()
 *     provider.enrollUserPresence()
 *
 *     // 5. Finalize - uses same client
 *     provider.finalize()
 * }
 * ```
 *
 * @param data JSON string containing initialization data from QR code scan, including
 *             optional `ignoreSSLCertificate` flag
 *
 * @see MFARegistrationDescriptor
 * @see NetworkHelper.allowInsecureSSL
 * @see NetworkHelper.createInsecureClient
 */
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

    override val canEnrollOneTimePasscode: Boolean
        get() = ::metaData.isInitialized && metaData.totpUri.toString().isNotEmpty()

    private val initializationInfo: InitializationInfo
    private var biometricFactor: BiometricFactorInfo? = null
    private var userPresenceFactor: UserPresenceFactorInfo? = null
    private lateinit var tokenInfo: TokenInfo
    private lateinit var metaData: Metadata
    private lateinit var authenticatorId: String
    private lateinit var registrationHttpClient: HttpClient

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

            // Create appropriate HTTP client based on SSL certificate flag
            // This implements the two-level security model:
            // 1. initializationInfo.ignoreSSLCertificate (from QR code) indicates need
            // 2. NetworkHelper.allowInsecureSSL (app-level) grants permission
            // Store the client for use throughout the registration process
            registrationHttpClient = if (initializationInfo.ignoreSSLCertificate) {
                // Use insecure client for this registration
                // Will throw exception if NetworkHelper.allowInsecureSSL is false
                NetworkHelper.createInsecureClient()
            } else {
                // Use provided client (default secure client or custom)
                httpClient
            }

            val responseDetail = registrationHttpClient.get {
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
            attributes["account_name"] = this.accountName
            attributes["push_token"] = this.pushToken
            val tenantId = UUID.randomUUID().toString()
            attributes["tenant_id"] = tenantId

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
                httpClient = registrationHttpClient
            )

            responseToken.fold(
                onSuccess = { tokenInfo ->
                    this.tokenInfo = tokenInfo
                    // Verify server returned an authenticator_id
                    if (tokenInfo.additionalData["authenticator_id"] !is String) return Result.failure(
                        MFARegistrationException.MissingAuthenticatorIdentifier()
                    )
                    // Use the tenant_id we generated, not the server's authenticator_id
                    authenticatorId = tenantId

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

    override suspend fun enrollBiometric(httpClient: HttpClient?) {
        val activeHttpClient: HttpClient = httpClient ?: registrationHttpClient
        if (canEnrollFingerprint) {
            performSignatureEnrollment(
                type = EnrollableType.FINGERPRINT,
                activeHttpClient = activeHttpClient
            )
        } else if (canEnrollFace) {
            performSignatureEnrollment(
                type = EnrollableType.FACE,
                activeHttpClient = activeHttpClient
            )
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

        val factor =
            metaData.availableFactors.first { it.type == type } as SignatureEnrollableFactor

        if (!factor.enabled) throw MFARegistrationException.SignatureMethodNotEnabled(factor.type)

        val algorithm = try {
            HashAlgorithmType.forSigning(factor.algorithm)
        } catch (_: HashAlgorithmException.InvalidHash) {
            throw MFARegistrationException.InvalidAlgorithm(factor.algorithm)
        }

        val keyName = "${authenticatorId}.${type}"

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
        httpClient: HttpClient?
    ) {
        val pending = pendingBiometricEnrollment
            ?: throw MFARegistrationException.InvalidPendingEnrollment()

        pendingBiometricEnrollment = null
        val activeHttpClient: HttpClient = httpClient ?: registrationHttpClient

        // On-premise enrollment uses an SCIM PATCH with publicKey + keyHandle only.
        // The CryptoObject has already unlocked the key via biometric authentication;
        // no separate signedData field is required in the request body.
        enroll(
            pending.type,
            pending.factor,
            pending.keyName,
            HashAlgorithmType.fromString(pending.algorithm),
            pending.publicKey,
            activeHttpClient
        )
    }

    override suspend fun enrollUserPresence(httpClient: HttpClient?) {
        if (!canEnrollUserPresence)
            throw MFARegistrationException.NoEnrollableFactors(EnrollableType.USER_PRESENCE)

        val activeHttpClient: HttpClient = httpClient ?: registrationHttpClient
        performSignatureEnrollment(
            type = EnrollableType.USER_PRESENCE,
            activeHttpClient = activeHttpClient
        )
    }

    override suspend fun enrollOneTimePasscode(httpClient: HttpClient?): OTPAuthenticator {
        log.entering()

        require(::tokenInfo.isInitialized) { "TokenInfo must be initialized. Call initiate() first." }
        require(::metaData.isInitialized) { "MetaData must be initialized. Call initiate() first." }
        require(::authenticatorId.isInitialized) { "Authenticator ID must be initialized. Call initiate() first." }

        if (!canEnrollOneTimePasscode) {
            throw MFARegistrationException.NoEnrollableFactors(EnrollableType.TOTP)
        }

        val activeHttpClient: HttpClient = httpClient ?: registrationHttpClient

        return try {
            val response = activeHttpClient.get {
                url(metaData.totpUri)
                accept(ContentType.Application.Json)
                bearerAuth(tokenInfo.accessToken)
            }

            if (!response.status.isSuccess()) {
                throw MFARegistrationException.General(
                    "Failed to enroll TOTP: ${response.status.value} - ${response.bodyAsText()}"
                )
            }

            // Parse the JSON response
            // Response format: {"period":"30","secretKeyUrl":"otpauth://totp/...","secretKey":"...","digits":"6","username":"...","algorithm":"HmacSHA1"}
            val responseBody = response.bodyAsText()
            val jsonResponse = decoder.decodeFromString<JsonObject>(responseBody)

            // Extract base URI (contains secret and issuer)
            val baseUri = jsonResponse["secretKeyUrl"]?.jsonPrimitive?.content
                ?: throw MFARegistrationException.FailedToParse(
                    IllegalArgumentException("Missing 'secretKeyUrl' field in TOTP response")
                )

            // Extract additional parameters from JSON
            val digits = jsonResponse["digits"]?.jsonPrimitive?.content ?: "6"
            val period = jsonResponse["period"]?.jsonPrimitive?.content ?: "30"
            val algorithm = jsonResponse["algorithm"]?.jsonPrimitive?.content ?: "HmacSHA1"

            // Convert algorithm from HmacSHA1 format to SHA1 format for otpauth URI
            val algorithmParam = when {
                algorithm.startsWith("Hmac", ignoreCase = true) -> algorithm.substring(4)
                    .uppercase()

                else -> algorithm.uppercase()
            }

            // Construct complete TOTP URI with all parameters
            val completeUri = if (baseUri.contains("?")) {
                "$baseUri&digits=$digits&period=$period&algorithm=$algorithmParam"
            } else {
                "$baseUri?digits=$digits&period=$period&algorithm=$algorithmParam"
            }

            // Use OTPAuthenticator.fromQRScan to parse the complete otpauth:// URI
            val otpAuthenticator = OTPAuthenticator.fromQRScan(completeUri)
                ?: throw MFARegistrationException.FailedToParse(
                    IllegalArgumentException("Invalid TOTP URI format: $completeUri")
                )

            log.exiting()
            otpAuthenticator

        } catch (e: MFARegistrationException) {
            log.exiting()
            throw e
        } catch (e: Exception) {
            log.exiting()
            throw MFARegistrationException.General("TOTP enrollment failed: ${e.message}", e)
        }
    }


    private suspend fun performSignatureEnrollment(
        type: EnrollableType,
        activeHttpClient: HttpClient
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

        val keyName = "${authenticatorId}.${type}"
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
            activeHttpClient
        )
    }


    @OptIn(InternalSerializationApi::class)
    private suspend fun enroll(
        type: EnrollableType,
        signatureEnrollableFactor: SignatureEnrollableFactor,
        keyName: String,
        algorithm: HashAlgorithmType,
        publicKey: String,
        activeHttpClient: HttpClient
    ) {

        try {
            log.entering()

            val path =
                "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:${type}Methods"
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

            val response = activeHttpClient.patch {
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

                        EnrollableType.TOTP, EnrollableType.HOTP -> {

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
    override suspend fun finalize(httpClient: HttpClient?): Result<MFAAuthenticatorDescriptor> {
        return try {
            log.entering()

            val activeHttpClient: HttpClient = httpClient ?: registrationHttpClient

            // Save original additional data from initial token response
            // This preserves fields like display_name, authenticator_id, ISV_push_enabled, etc.
            val originalAdditionalData = tokenInfo.additionalData

            log.debug("=== FINALIZE: Original token additionalData ===")
            originalAdditionalData.forEach { (key, value) ->
                log.debug("  {}: {}", key, value)
            }

            // Generate requestBody for token refresh based on OnPremiseAuthenticatorService.refreshToken
            val attributes = MFAAttributeInfo.dictionary(snakeCaseKey = true).toMutableMap()
            attributes["account_name"] = accountName
            attributes["push_token"] = pushToken
            attributes["tenant_id"] = authenticatorId

            val requestBody = mutableMapOf(
                "grant_type" to "refresh_token",
                "client_id" to initializationInfo.clientId,
                "refresh_token" to tokenInfo.refreshToken
            )

            attributes.forEach { (key, value) ->
                requestBody[key] = value.toString()
            }

            val response = activeHttpClient.post {
                url(metaData.registrationUri.toString())
                accept(ContentType.Application.Json)
                contentType(ContentType.Application.FormUrlEncoded)
                setBody(requestBody.toList().formUrlEncode())
            }

            if (response.status.isSuccess()) {
                response.bodyAsText().let { responseBodyData ->
                    log.debug("=== FINALIZE: Server refresh response ===")
                    log.debug(responseBodyData)

                    val refreshedToken: TokenInfo = decoder.decodeFromString(responseBodyData)

                    log.debug("=== FINALIZE: Refreshed token additionalData ===")
                    refreshedToken.additionalData.forEach { (key, value) ->
                        log.debug("  {}: {}", key, value)
                    }

                    // Merge additional data: preserve original fields, allow refresh response to override
                    val mergedAdditionalData =
                        originalAdditionalData + refreshedToken.additionalData

                    log.debug("=== FINALIZE: Merged additionalData (BEFORE storing) ===")
                    mergedAdditionalData.forEach { (key, value) ->
                        log.debug("  {}: {}", key, value)
                    }

                    tokenInfo = refreshedToken.copy(
                        additionalData = mergedAdditionalData
                    )

                    log.debug("=== FINALIZE: Final tokenInfo to be stored ===")
                    log.debug("  accessToken: ${tokenInfo.accessToken}")
                    log.debug("  refreshToken: ${tokenInfo.refreshToken}")
                    log.debug("  expiresIn: ${tokenInfo.expiresIn}")
                    log.debug("  additionalData:")
                    tokenInfo.additionalData.forEach { (key, value) ->
                        log.debug("    {}: {}", key, value)
                    }
                }

                log.debug("=== FINALIZE: Creating OnPremiseAuthenticator ===")
                log.debug("  id (authenticatorId): $authenticatorId")
                log.debug("  serviceName: ${metaData.serviceName}")
                log.debug("  accountName: $accountName")
                log.debug("  refreshUri: {}", metaData.registrationUri)
                log.debug("  transactionUri: {}", metaData.transactionUri)

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