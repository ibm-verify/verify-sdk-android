/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import io.ktor.client.HttpClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume


/**
 * Defines the contract for multi-factor authentication registration providers.
 *
 * This interface provides the core functionality for enrolling authentication factors
 * and finalizing the registration process. Implementations handle the specific details
 * of communicating with either cloud-based or on-premise authentication services.
 *
 * @param Authenticator The type of authenticator descriptor returned upon successful registration.
 *
 * @see CloudRegistrationProvider
 * @see OnPremiseRegistrationProvider
 */
interface MFARegistrationDescriptor<out Authenticator : MFAAuthenticatorDescriptor> {

    /**
     * The push notification token for the device.
     *
     * This token is typically obtained from Firebase Cloud Messaging (FCM) and is used
     * to send push notifications for transaction verification and other MFA operations.
     */
    var pushToken: String

    /**
     * The service name associated with this registration.
     *
     * This is the name of the service or tenant (e.g. "IBM Verify") that the authenticator
     * is being registered with.  Available after [MFARegistrationController.initiate] completes.
     */
    val serviceName: String

    /**
     * The account name associated with this registration.
     *
     * This is typically the user's display name or identifier that will be shown
     * in the authenticator application.
     */
    var accountName: String

    /**
     * Indicates whether user authentication is required for biometric operations.
     *
     * When `true`, the user must authenticate (e.g., via PIN, pattern, or password)
     * before biometric operations can be performed.
     */
    var authenticationRequired: Boolean

    /**
     * Indicates whether biometric keys should be invalidated when new biometrics are enrolled.
     *
     * When `true`, adding new fingerprints or face data will invalidate existing
     * biometric keys, requiring re-enrollment of the MFA factor.
     */
    var invalidatedByBiometricEnrollment: Boolean

    /**
     * Indicates whether user presence verification can be enrolled.
     *
     * User presence verification typically requires the user to confirm their presence
     * through a simple action like tapping a button, without requiring biometric authentication.
     *
     * @return `true` if user presence enrollment is available, `false` otherwise.
     */
    val canEnrollUserPresence: Boolean

    /**
     * Indicates whether biometric verification can be enrolled.
     *
     * Biometric verification uses fingerprint, face recognition, or other biometric
     * methods to authenticate the user.
     *
     * @return `true` if biometric enrollment is available, `false` otherwise.
     */
    val canEnrollBiometric: Boolean

    /**
     * The number of authentication factors available for enrollment.
     *
     * This count includes all factors that can still be enrolled, such as TOTP,
     * user presence, and biometric verification.
     *
     * @return The count of available enrollments.
     */
    val countOfAvailableEnrollments: Int

    /**
     * Enrolls biometric verification as an authentication factor.
     *
     * This method registers the device's biometric capabilities (fingerprint, face recognition)
     * as an authentication factor. The biometric data is stored securely on the device and
     * never transmitted to the server.
     *
     * When [authenticationRequired] is `true` the biometric key is generated with
     * `setUserAuthenticationRequired(true)` and cannot be used for signing without first
     * authenticating the user.  In that case this method throws
     * [MFARegistrationException.BiometricAuthenticationRequired] carrying a
     * [BiometricPrompt.CryptoObject] that wraps the pre-initialised [java.security.Signature].
     * Pass the [BiometricPrompt.CryptoObject] to [BiometricPrompt.authenticate] and, after
     * successful authentication, call [enrollBiometric(BiometricPrompt.CryptoObject)] with the
     * authenticated [BiometricPrompt.CryptoObject] from
     * [BiometricPrompt.AuthenticationResult.getCryptoObject].
     *
     * ## Usage
     * ```kotlin
     * try {
     *     provider.enrollBiometric()
     * } catch (e: MFARegistrationException.BiometricAuthenticationRequired) {
     *     biometricPrompt.authenticate(promptInfo, e.cryptoObject)
     *     // then in onAuthenticationSucceeded:
     *     //   provider.enrollBiometric(result.cryptoObject!!)
     * }
     * ```
     *
     * @param httpClient Optional HTTP client instance for making network requests.
     *                   Defaults to [NetworkHelper.getInstance].
     *
     * @throws MFARegistrationException.BiometricAuthenticationRequired when
     *         [authenticationRequired] is `true` — the caller must show a [BiometricPrompt]
     *         with the provided [BiometricPrompt.CryptoObject] and then call
     *         [enrollBiometric(BiometricPrompt.CryptoObject)].
     * @throws MFARegistrationException for other enrollment failures (network errors,
     *         invalid state, server rejection).
     */
    @Throws
    suspend fun enrollBiometric(httpClient: HttpClient = NetworkHelper.getInstance)

    /**
     * Enrolls biometric verification using a hardware-unlocked [BiometricPrompt.CryptoObject]
     * obtained from [BiometricPrompt.AuthenticationResult.getCryptoObject] in
     * [BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded].
     *
     * Call this overload after catching [MFARegistrationException.BiometricAuthenticationRequired]
     * from [enrollBiometric] and completing [BiometricPrompt] authentication.  The [cryptoObject]
     * carries the authenticated [java.security.Signature] that signs the enrollment challenge
     * without ever exposing the raw private key.
     *
     * @param cryptoObject The authenticated [BiometricPrompt.CryptoObject] from the biometric result.
     * @param httpClient Optional HTTP client instance. Defaults to [NetworkHelper.getInstance].
     *
     * @throws MFARegistrationException if enrollment fails.
     */
    @Throws
    suspend fun enrollBiometric(
        cryptoObject: BiometricPrompt.CryptoObject,
        httpClient: HttpClient = NetworkHelper.getInstance
    )

    /**
     * Enrolls biometric verification as an authentication factor, automatically showing a
     * [BiometricPrompt] dialog when [authenticationRequired] is `true`.
     *
     * This overload handles the full two-phase enrollment flow internally:
     * 1. Calls [enrollBiometric] to generate the key pair.
     * 2. If [MFARegistrationException.BiometricAuthenticationRequired] is thrown, shows a
     *    [BiometricPrompt] dialog using the provided [activity] and [promptInfo].
     * 3. On successful authentication, calls [enrollBiometric(BiometricPrompt.CryptoObject)]
     *    with the hardware-unlocked [BiometricPrompt.CryptoObject] to complete enrollment.
     *
     * The coroutine suspends while the biometric dialog is displayed and resumes once the
     * user authenticates or an error occurs.
     *
     * ## Usage
     * ```kotlin
     * provider.enrollBiometric(
     *     activity = this,
     *     promptInfo = BiometricPrompt.PromptInfo.Builder()
     *         .setTitle("Enroll Biometric")
     *         .setSubtitle("Authenticate to enable biometric sign-in")
     *         .setNegativeButtonText("Cancel")
     *         .build()
     * ).onSuccess {
     *     // Enrollment complete
     * }.onFailure { error ->
     *     when (error) {
     *         is MFARegistrationException.BiometricAuthenticationCancelled ->
     *             println("Cancelled: ${error.errString}")
     *         else -> println("Enrollment failed: ${error.message}")
     *     }
     * }
     * ```
     *
     * @param activity The [FragmentActivity] used to host the [BiometricPrompt] dialog.
     * @param promptInfo The [BiometricPrompt.PromptInfo] describing the dialog title, subtitle,
     *                   and button labels. Use [BiometricPrompt.PromptInfo.Builder] to configure
     *                   the title, subtitle, description, and negative button text shown to the user.
     * @param httpClient Optional HTTP client instance. Defaults to [NetworkHelper.getInstance].
     *
     * @return A [Result] containing:
     *         - [Result.success] with [Unit] if enrollment completed successfully.
     *         - [Result.failure] with [MFARegistrationException.BiometricAuthenticationCancelled]
     *           if the user cancelled or dismissed the dialog, or if the system reported an
     *           unrecoverable authentication error.
     *         - [Result.failure] with another [MFARegistrationException] subclass if enrollment
     *           failed for any other reason (network error, server rejection, etc.).
     */
    suspend fun enrollBiometric(
        activity: FragmentActivity,
        promptInfo: BiometricPrompt.PromptInfo,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<Unit> {
        return try {
            enrollBiometric(httpClient)
            Result.success(Unit)
        } catch (e: MFARegistrationException.BiometricAuthenticationRequired) {
            // Show the BiometricPrompt on the main thread and suspend until the result arrives.
            // Only the BiometricPrompt construction and authenticate() call need to be on Main;
            // the coroutine itself suspends without blocking the thread.
            val cryptoResult = suspendCancellableCoroutine { continuation ->
                val executor = ContextCompat.getMainExecutor(activity)
                val prompt = BiometricPrompt(
                    activity,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult
                        ) {
                            val cryptoObject = result.cryptoObject
                            if (cryptoObject != null) {
                                continuation.resume(Result.success(cryptoObject))
                            } else {
                                continuation.resume(
                                    Result.failure(MFARegistrationException.InvalidPendingEnrollment())
                                )
                            }
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence
                        ) {
                            continuation.resume(
                                Result.failure(
                                    MFARegistrationException.BiometricAuthenticationCancelled(
                                        errorCode,
                                        errString.toString()
                                    )
                                )
                            )
                        }

                        override fun onAuthenticationFailed() {
                            // A single attempt failed — the prompt stays open; do nothing here.
                            // The coroutine will resume via onAuthenticationSucceeded or
                            // onAuthenticationError.
                        }
                    }
                )
                // BiometricPrompt must be shown on the main thread.
                activity.runOnUiThread {
                    prompt.authenticate(promptInfo, e.cryptoObject)
                }
                continuation.invokeOnCancellation { prompt.cancelAuthentication() }
            }
            // Complete enrollment with the hardware-unlocked CryptoObject, or propagate the error.
            // Use try/catch instead of runCatching to avoid swallowing CancellationException.
            cryptoResult.fold(
                onSuccess = { authenticatedCryptoObject ->
                    try {
                        enrollBiometric(authenticatedCryptoObject, httpClient)
                        Result.success(Unit)
                    } catch (ex: CancellationException) {
                        throw ex  // Re-throw to preserve structured concurrency.
                    } catch (ex: Throwable) {
                        Result.failure(ex)
                    }
                },
                onFailure = { Result.failure(it) }
            )
        } catch (e: CancellationException) {
            throw e  // Re-throw to preserve structured concurrency.
        } catch (e: Throwable) {
            Result.failure(e)
        }
    }

    /**
     * Enrolls user presence verification as an authentication factor.
     *
     * This method registers a simpler form of verification that confirms the user's
     * presence without requiring biometric authentication. This is typically used
     * for lower-security scenarios or as a fallback when biometrics are unavailable.
     *
     * @param httpClient Optional HTTP client instance for making network requests.
     *                   Defaults to [NetworkHelper.getInstance].
     *
     * @throws MFARegistrationException if enrollment fails due to network errors,
     *         invalid state, or server rejection.
     */
    @Throws
    suspend fun enrollUserPresence(httpClient: HttpClient = NetworkHelper.getInstance)

    /**
     * Finalizes the registration process and returns the registered authenticator.
     *
     * This method completes the registration flow by submitting all enrolled factors
     * to the authentication service and retrieving the final authenticator descriptor.
     * After successful finalization, the authenticator can be used for authentication
     * operations.
     *
     * @param httpClient Optional HTTP client instance for making network requests.
     *                   Defaults to [NetworkHelper.getInstance].
     *
     * @return A [Result] containing either:
     *         - Success: An [MFAAuthenticatorDescriptor] representing the registered authenticator
     *         - Failure: An [MFARegistrationException] indicating why finalization failed
     *
     * @throws MFARegistrationException if finalization fails due to network errors,
     *         incomplete enrollment, or server rejection.
     */
    @Throws
    suspend fun finalize(httpClient: HttpClient = NetworkHelper.getInstance): Result<MFAAuthenticatorDescriptor>
}

/**
 * Type alias representing a JSON string containing registration initiation data.
 */
typealias RegistrationInitiation = String