/*
 *  Copyright contributors to the IBM Verify FIDO2 SDK for Android project
 */

package com.ibm.security.verifysdk.fido2

import com.ibm.security.verifysdk.core.Error
import com.ibm.security.verifysdk.core.VerifySdkException

/**
 * Represents an exception specific to biometric authentication.
 *
 * This class is used to indicate errors related to biometric authentication
 * processes. It extends the standard Exception class and provides a constructor
 * that accepts a message describing the error.
 *
 * @param description A string describing the exception.
 * @param cause The underlying cause of the exception, if any.
 *
 * @constructor Creates a BiometricAuthenticationException instance with the given message.
 */
internal class BiometricAuthenticationException(
    description: String,
    cause: Throwable? = null
) : VerifySdkException(Error("biometric_authentication_failed", description), cause)
