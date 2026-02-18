/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

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
     * Represents a general or otherwise uncategorized registration exception.
     */
    class General(description: String, cause: Throwable? = null) :
        MFARegistrationException(Error("general_registration_error", description), cause)
}