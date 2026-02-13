/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.serializer.DefaultJson
import com.ibm.security.verifysdk.mfa.api.CloudRegistrationProvider
import com.ibm.security.verifysdk.mfa.api.OnPremiseRegistrationProvider
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.slf4j.LoggerFactory

/**
 * An instance you use to instantiate an [MFARegistrationDescriptor] to perform enrollment operations.
 *
 * The [MFARegistrationController] is the entry point for multi-factor authentication registration.
 * It parses QR code data and initiates the registration process with either Cloud or On-Premise
 * authentication providers.
 *
 * ## Usage Example
 * ```kotlin
 * // Value from QR code scan
 * val qrScanResult = """
 *     {
 *         "code":"A1B2C3D4",
 *         "options":"ignoreSslCerts=true",
 *         "details_url":"https://sdk.verify.ibm.com/mga/sps/mmfa/user/mgmt/details",
 *         "version": 1,
 *         "client_id":"IBMVerify"
 *     }
 * """
 *
 * // Create the registration controller
 * val controller = MFARegistrationController(qrScanResult)
 *
 * // Check if SSL certificate validation should be ignored
 * if (controller.ignoreSSLCertificate) {
 *     // Alert user about self-signed certificate
 * }
 *
 * // Initiate the provider
 * val result = controller.initiate(
 *     accountName = "My Account",
 *     pushToken = "abc123"
 * )
 *
 * result.onSuccess { provider ->
 *     // Get the next enrollment
 *     val factor = provider.nextEnrollment()
 *     factor?.let {
 *         // Enroll the factor
 *         provider.enroll()
 *     }
 *
 *     // Finalize and get the authenticator
 *     val authenticator = provider.finalize().getOrNull()
 * }
 * ```
 *
 * @property data The JSON string that initiates multi-factor registration, typically obtained from a QR code.
 * @constructor Creates an instance with JSON value from a QR code scan.
 *
 * @see MFARegistrationDescriptor
 * @see CloudRegistrationProvider
 * @see OnPremiseRegistrationProvider
 */
class MFARegistrationController(private var data: String) {

    private val log = LoggerFactory.getLogger(javaClass)

    /**
     * A Boolean value that indicates whether the authenticator will ignore SSL certificate challenges.
     *
     * Before invoking [initiate], this value can be used to alert the user that the certificate
     * connecting the service is self-signed.
     *
     * @return `true` when the service is using a self-signed certificate, `false` otherwise.
     */
    var ignoreSSLCertificate: Boolean = false
        private set

    init {

        val jsonObject: JsonObject = DefaultJson.parseToJsonElement(data).jsonObject

        jsonObject.let {
            it.contains("options").let {
                this.ignoreSSLCertificate =
                    jsonObject["options"].toString()
                        .filter { c -> !c.isWhitespace() } == "ignoreSslCerts=true"
            }
        }
    }

    /**
     * Initiates the registration of a multi-factor authenticator.
     *
     * This method attempts to create either a [CloudRegistrationProvider] or [OnPremiseRegistrationProvider]
     * based on the JSON data format. It will try Cloud registration first, and if that fails, attempt
     * On-Premise registration.
     *
     * ## Usage Example
     * ```kotlin
     * val controller = MFARegistrationController(qrCodeData)
     *
     * val result = controller.initiate(
     *     accountName = "John Doe",
     *     skipTotpEnrollment = true,
     *     pushToken = "device-push-token-123"
     * )
     *
     * result.onSuccess { provider ->
     *     // Proceed with enrollment
     *     while (provider.nextEnrollment() != null) {
     *         provider.enroll()
     *     }
     *     val authenticator = provider.finalize()
     * }
     *
     * result.onFailure { error ->
     *     // Handle registration error
     *     println("Registration failed: ${error.message}")
     * }
     * ```
     *
     * @param accountName The account name associated with the service. This is typically the user's
     *                    display name or identifier.
     * @param skipTotpEnrollment A Boolean value that when set to `true`, the TOTP (Time-based One-Time Password)
     *                          authentication method enrollment attempt will be skipped. Default is `true`.
     * @param pushToken A token that identifies the device for push notifications. This is typically obtained
     *                  from Firebase Cloud Messaging (FCM). Pass an empty string if push notifications are
     *                  not required. Default is an empty string.
     * @param additionalHeaders (Optional) A map of additional HTTP headers to be included in the registration
     *                         request. This is primarily used for on-premise registrations. Default is `null`.
     *
     * @return A [Result] containing either:
     *         - Success: An [MFARegistrationDescriptor] that can be used to perform enrollment operations
     *         - Failure: An [MFARegistrationException] indicating why the registration failed
     *
     * @throws MFARegistrationException.InvalidFormat if the JSON data cannot be parsed as either Cloud or
     *                                            On-Premise registration format.
     *
     * @see MFARegistrationDescriptor
     * @see MFARegistrationException
     */
    suspend fun initiate(
        accountName: String,
        pushToken: String? = "",
        additionalHeaders: HashMap<String, String>? = null
    ): Result<MFARegistrationDescriptor<MFAAuthenticatorDescriptor>> {

        try {
            CloudRegistrationProvider(data).let { cloudRegistrationProvider ->
                cloudRegistrationProvider.initiate(accountName, pushToken)
                    .let { resultInitiate ->
                        resultInitiate.onSuccess {
                            return Result.success(cloudRegistrationProvider)
                        }
                        resultInitiate.onFailure {
                            return Result.failure(it)
                        }
                    }
            }
        } catch (t: Throwable) {
            t.localizedMessage?.let { localizedMessage ->
                log.error(localizedMessage)
            }
        }

        try {
            OnPremiseRegistrationProvider(data).let { onPremiseRegistrationProvider ->
                onPremiseRegistrationProvider.initiate(
                    accountName,
                    pushToken,
                    additionalHeaders
                )
                    .let { resultInitiate ->
                        resultInitiate.onSuccess {
                            return Result.success(onPremiseRegistrationProvider)
                        }
                        resultInitiate.onFailure {
                            return Result.failure(it)
                        }
                    }
            }
        } catch (t: Throwable) {
            t.localizedMessage?.let { localizedMessage ->
                log.error(localizedMessage)
            }
        }

        return Result.failure(MFARegistrationException.InvalidFormat())
    }
}