/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.Error
import com.ibm.security.verifysdk.core.VerifySdkException

/**
 * A sealed class representing specific exceptions that can occur within the MFA service.
 *
 * Each exception includes a unique ID and a descriptive message, and can optionally wrap a `cause`
 * for better debugging.
 */
sealed class MFAServiceException(error: Error, cause: Throwable? = null) : VerifySdkException(error, cause) {

    /**
     * Indicates that the signing hash algorithm was invalid.
     */
    class InvalidSigningHash(cause: Throwable? = null) :
        MFAServiceException(Error("invalid_signing_hash", "The signing hash algorithm was invalid."), cause)

    /**
     * Indicates that no pending transaction was available to complete.
     */
    class InvalidPendingTransaction(cause: Throwable? = null) :
        MFAServiceException(
            Error("invalid_pending_transaction", "No pending transaction was available to complete."),
            cause
        )

    /**
     * Indicates that a serialization conversion failed.
     */
    class SerializationFailed(cause: Throwable? = null) :
        MFAServiceException(Error("serialization_failed", "Serialization conversion failed."), cause)

    /**
     * Indicates that the response data was invalid or in an unexpected format.
     */
    class InvalidDataResponse(cause: Throwable? = null) :
        MFAServiceException(Error("invalid_data_response", "The response data was invalid."), cause)

    /**
     * Indicates that a JSON decoding operation failed.
     */
    class DecodingFailed(cause: Throwable? = null) :
        MFAServiceException(Error("decoding_failed", "The JSON decoding operation failed."), cause)

    /**
     * Indicates that the SDK was unable to create the pending transaction.
     */
    class UnableToCreateTransaction(cause: Throwable? = null) :
        MFAServiceException(
            Error("unable_to_create_transaction", "Unable to create the pending transaction."),
            cause
        )

    /**
     * Represents a general or otherwise uncategorized MFA exception.
     */
    class General(description: String, cause: Throwable? = null) :
        MFAServiceException(Error("general_mfa_error", description), cause)
}
