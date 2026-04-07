/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.biometric.BiometricPrompt
import com.ibm.security.verifysdk.core.Error
import com.ibm.security.verifysdk.core.VerifySdkException

/**
 * A sealed class representing specific exceptions that can occur during MFA registration.
 *
 * Each exception includes a unique ID and a descriptive message, and can optionally wrap a `cause`
 * for better debugging.
 */
sealed class MFARegistrationException(error: Error, cause: Throwable? = null) :
    VerifySdkException(error, cause) {

    /**
     * Indicates that a JSON value failed to be parsed.
     */
    class FailedToParse(cause: Throwable? = null) :
        MFARegistrationException(Error("failed_to_parse", "Failed to parse JSON value."), cause)

    /**
     * Indicates that the JSON format was invalid for creating an MFARegistrationDescriptor.
     */
    class InvalidFormat(cause: Throwable? = null) :
        MFARegistrationException(
            Error(
                "invalid_format",
                "Invalid JSON format to create an MFARegistrationDescriptor."
            ), cause
        )

    /**
     * Indicates that no enrollable factors were available for enrollment.
     */
    class NoEnrollableFactors(enrollableType: EnrollableType? = null, cause: Throwable? = null) :
        MFARegistrationException(
            Error(
                "no_enrollable_factors",
                if (enrollableType != null) {
                    "No enrollable factors available for enrollment type: ${enrollableType.name}"
                } else {
                    "No enrollable factors available for enrollment."
                }
            ),
            cause
        )

    /**
     * Indicates that factor enrollment failed.
     */
    class EnrollmentFailed(cause: Throwable? = null) :
        MFARegistrationException(Error("enrollment_failed", "Factor enrollment failed."), cause)

    /**
     * Indicates that data initialization failed.
     */
    class DataInitializationFailed(cause: Throwable? = null) :
        MFARegistrationException(
            Error("data_initialization_failed", "Initialization failed."),
            cause
        )

    /**
     * Indicates that the authenticator identifier was missing from the OAuth token.
     */
    class MissingAuthenticatorIdentifier(cause: Throwable? = null) :
        MFARegistrationException(
            Error(
                "missing_authenticator_identifier",
                "Authenticator identifier missing from OAuth token."
            ), cause
        )

    /**
     * Indicates that the multi-factor registration data was invalid.
     */
    class InvalidRegistrationData(cause: Throwable? = null) :
        MFARegistrationException(
            Error(
                "invalid_registration_data",
                "Invalid multi-factor registration data."
            ), cause
        )

    /**
     * Indicates that a signature method is not enabled.
     */
    class SignatureMethodNotEnabled(
        enrollableType: EnrollableType? = null,
        cause: Throwable? = null
    ) :
        MFARegistrationException(
            Error(
                "signature_method_not_enabled",
                if (enrollableType != null) {
                    "Signature method '$enrollableType' is not enabled."
                } else {
                    "Signature method is not enabled."
                }
            ),
            cause
        )

    /**
     * Indicates that an invalid algorithm was provided.
     */
    class InvalidAlgorithm(algorithm: String, cause: Throwable? = null) :
        MFARegistrationException(
            Error(
                "invalid_algorithm",
                "The resolved algorithm `$algorithm` is not valid."
            ),
            cause
        )

    /**
     * Thrown by [MFARegistrationDescriptor.enrollBiometric] when [authenticationRequired] is
     * `true` and the biometric key cannot be used for signing without first authenticating the
     * user via [BiometricPrompt].
     *
     * The [cryptoObject] wraps a [java.security.Signature] pre-initialised with the locked
     * private key.  Pass it to [BiometricPrompt.authenticate] so the hardware can unlock the
     * key.  After successful authentication, call
     * [MFARegistrationDescriptor.enrollBiometric(BiometricPrompt.CryptoObject)] with the
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
     */
    class BiometricAuthenticationRequired(
        val cryptoObject: BiometricPrompt.CryptoObject,
        cause: Throwable? = null
    ) : MFARegistrationException(
        Error(
            "biometric_authentication_required",
            "Biometric authentication is required to complete enrollment. " +
                "Pass the provided CryptoObject to BiometricPrompt.authenticate(), " +
                "then call enrollBiometric(cryptoObject) in onAuthenticationSucceeded."
        ),
        cause
    )

    /**
     * Indicates that [enrollBiometric(BiometricPrompt.CryptoObject)] was called without a
     * prior [enrollBiometric] call that threw [BiometricAuthenticationRequired].
     */
    class InvalidPendingEnrollment(cause: Throwable? = null) :
        MFARegistrationException(
            Error(
                "invalid_pending_enrollment",
                "No pending biometric enrollment found. " +
                    "Call enrollBiometric() first and handle BiometricAuthenticationRequired."
            ),
            cause
        )

    /**
     * Thrown by the [MFARegistrationDescriptor.enrollBiometric(FragmentActivity, PromptInfo)]
     * overload when the user cancels or dismisses the [BiometricPrompt] dialog, or when the
     * system reports an unrecoverable authentication error.
     *
     * @param errorCode The [BiometricPrompt] error code (e.g.
     *   [BiometricPrompt.ERROR_USER_CANCELED], [BiometricPrompt.ERROR_NEGATIVE_BUTTON]).
     * @param errString The human-readable error message returned by the system.
     */
    class BiometricAuthenticationCancelled(
        val errorCode: Int,
        val errString: String,
        cause: Throwable? = null
    ) : MFARegistrationException(
        Error(
            "biometric_authentication_cancelled",
            "Biometric authentication was cancelled or failed with error $errorCode: $errString"
        ),
        cause
    )

    /**
     * Represents a general or otherwise uncategorized registration exception.
     */
    class General(description: String, cause: Throwable? = null) :
        MFARegistrationException(Error("general_registration_error", description), cause)
}