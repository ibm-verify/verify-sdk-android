/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.Error
import com.ibm.security.verifysdk.core.VerifySdkException

/**
 * Represents exceptions related to hash algorithm operations.
 *
 * @since 3.0.2
 */
sealed class HashAlgorithmException(error: Error, cause: Throwable? = null) :
    VerifySdkException(error, cause) {

    /**
     * Indicates that the hash type is invalid.
     */
    class InvalidHash(cause: Throwable? = null) :
        HashAlgorithmException(Error("invalid_hash_type", "The hash type is invalid."), cause)
}
