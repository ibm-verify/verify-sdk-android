/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.mfa

import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricPrompt
import com.ibm.security.verifysdk.core.helper.KeystoreHelper

/**
 * An interface that defines the authenticator identifier and it's metadata.
 *
 * @since 3.0.2
 */
interface AuthenticatorDescriptor {
    /**
     * The unique identifier of the authenticator.  Typically represented as a `UUID`.
     */
    val id: String

    /**
     * The name of the service providing the authenicator.
     */
    val serviceName: String

    /**
     * The name of the account associated with the service.
     */
    var accountName: String
}

/**
 * Generates the private/public key pair returning the public key.
 *
 * @param keyName The name of the key to be created.
 * @param algorithm The cryptographic algorithm to be used (e.g., RSA, EC).
 * @param authenticationRequired A flag indicating whether user authentication is required for key usage. (default is (@code false))
 * @param base64EncodingOptions The options for Base64 encoding (default is Base64.NO_WRAP).
 * @return A Base64 encoded string representation of the generated key pair.
 */
internal fun generateKeys(
    keyName: String,
    algorithm: String,
    authenticationRequired: Boolean = false,
    invalidatedByBiometricEnrollment: Boolean = false,
    base64EncodingOptions: Int = Base64.NO_WRAP
): String {

    return Base64.encodeToString(
        KeystoreHelper.createKeyPair(
            keyName = keyName,
            algorithm = algorithm,
            purpose = KeyProperties.PURPOSE_SIGN,
            authenticationRequired = authenticationRequired,
            invalidatedByBiometricEnrollment = invalidatedByBiometricEnrollment
        ).encoded,
        base64EncodingOptions
    )
}

/**
 * Signs the provided data using the specified key and algorithm, then encodes the signature as a Base64 string.
 *
 * @param keyName The name of the key to be used for signing.
 * @param algorithm The hash algorithm to be used for signing (e.g., SHA1, SHA256).
 * @param dataToSign The data to be signed.
 * @param base64EncodingOptions The options for Base64 encoding (default is Base64.DEFAULT).
 * @return A Base64 encoded string representation of the signed data, or an empty string if signing fails.
 */
internal fun sign(
    keyName: String,
    algorithm: String,
    dataToSign: String,
    base64EncodingOptions: Int = Base64.DEFAULT
): String {

    val signatureAlgorithm: String = when (HashAlgorithmType.fromString(algorithm)) {
        HashAlgorithmType.SHA1 -> "SHA1withRSA"
        HashAlgorithmType.SHA256 -> "SHA256withRSA"
        HashAlgorithmType.SHA384 -> "SHA384withRSA"
        HashAlgorithmType.SHA512 -> "SHA512withRSA"
    }

    return KeystoreHelper.signData(keyName, signatureAlgorithm, dataToSign, base64EncodingOptions)
        ?: ""
}

/**
 * Signs the provided data using the specified BiometricPrompt.CryptoObject and encodes the signature
 * as a Base64 string.
 *
 * @param cryptoObject The BiometricPrompt.CryptoObject to be used for signing.
 * @param dataToSign The data to be signed.
 * @param base64EncodingOptions The options for Base64 encoding (default is Base64.DEFAULT).
 * @return A Base64 encoded string representation of the signed data, or an empty string if signing fails.
 */
internal fun sign(
    cryptoObject: BiometricPrompt.CryptoObject,
    dataToSign: String,
    base64EncodingOptions: Int = Base64.DEFAULT
): String {

    return KeystoreHelper.signData(cryptoObject, dataToSign, base64EncodingOptions) ?: ""
}
