/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core.helper

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.biometric.BiometricPrompt
import com.ibm.security.verifysdk.core.extension.entering
import com.ibm.security.verifysdk.core.extension.exiting
import org.slf4j.LoggerFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Comprehensive helper class for Android KeyStore operations.
 *
 * Provides unified key management for both symmetric (AES) and asymmetric (RSA, EC) keys,
 * including generation, retrieval, deletion, and cryptographic operations.
 *
 * ## Key Features:
 * - **AES Key Management**: Generate AES-256-GCM keys with optional StrongBox backing
 * - **Key Pair Management**: Generate RSA/EC key pairs for signing operations
 * - **Biometric Integration**: Support for biometric-protected keys and signing
 * - **Unified Deletion**: Single method to delete any key type
 * - **Private Key Wrapping**: Encrypt/decrypt private keys using AES
 *
 * ## Supported Key Types:
 * - **AES**: 256-bit symmetric keys for encryption (with StrongBox support)
 * - **RSA**: 2048-bit asymmetric keys for signing (configurable size)
 * - **EC**: secp256r1 elliptic curve keys for FIDO2
 *
 * ## Usage Examples:
 *
 * ### AES Key Management:
 * ```kotlin
 * // Generate or retrieve AES key with StrongBox support
 * val key = KeystoreHelper.getOrCreateAESKey("myEncryptionKey")
 *
 * // Delete any key type
 * KeystoreHelper.deleteKey("myKey")
 * ```
 *
 * ### Key Pair Management:
 * ```kotlin
 * // Generate RSA key pair for signing
 * val publicKey = KeystoreHelper.createKeyPair(
 *     keyName = "mySigningKey",
 *     algorithm = "SHA256withRSA",
 *     purpose = KeyProperties.PURPOSE_SIGN
 * )
 *
 * // Sign data
 * val signature = KeystoreHelper.signData("mySigningKey", "SHA256withRSA", dataToSign)
 * ```
 *
 * ### Biometric Authentication:
 * ```kotlin
 * // Create crypto object for biometric prompt
 * val cryptoObject = KeystoreHelper.getCryptoObject("myKey", "SHA256withRSA")
 *
 * // Sign with biometric authentication
 * val signature = KeystoreHelper.signData(cryptoObject, dataToSign)
 * ```
 *
 * ## Security Features:
 * - **StrongBox Support**: Automatic fallback when hardware-backed security unavailable
 * - **Biometric Protection**: Keys can require biometric authentication
 * - **Key Invalidation**: Keys can be invalidated on biometric enrollment changes
 * - **Secure Key Storage**: All keys stored in Android KeyStore (hardware-backed when available)
 *
 * @see <a href="https://developer.android.com/training/articles/keystore">Android KeyStore System</a>
 * @see <a href="https://developer.android.com/training/sign-in/biometric-auth">Biometric Authentication</a>
 */
@Suppress("BooleanMethodIsAlwaysInverted")
object KeystoreHelper {

    private val log = LoggerFactory.getLogger(javaClass)

    var keystoreType = "AndroidKeyStore"
        set(value) {
            val keyStore = KeyStore.getInstance(value)
            keyStore.load(null)
            field = value
        }

    var keySize: Int = 2048

    // https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature
    private val supportedAlgorithmsSigning: ArrayList<String> =
        arrayListOf("SHA1withRSA", "SHA256withRSA", "SHA512withRSA", "EC")

    /**
     * Generates a private and public key to sign data. An existing key pair with the same alias will
     * be deleted.
     * <p>
     * The key size is specific to provided algorithm and could be looked up from the algorithm-specific
     * parameters via <a href="https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder.html#setAlgorithmParameterSpec(java.security.spec.AlgorithmParameterSpec)">setAlgorithmParameterSpec</a>.
     *
     * @param keyName  the unique identifier of the key pair
     * @param algorithm  the standard string name of the algorithm to generate the key pair
     * @param purpose
     * @param authenticationRequired  indicates whether the generated key requires authentication
     *                               (fingerprint) in order to get access to it.
     * @param invalidatedByBiometricEnrollment  indicates whether the key should be invalidated on biometric enrollment.
     *                                          This is only supported since API level 24 (Nougat). For further details please
     *                                          see <a href="https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment(boolean)">setInvalidatedByBiometricEnrollment</a>
     *
     * @throws KeyStoreException  if the key could not be generated
     * @throws UnsupportedOperationException  if the `algorithm` is not supported
     */
    @Throws(KeyStoreException::class, UnsupportedOperationException::class)
    fun createKeyPair(
        keyName: String,
        algorithm: String,
        purpose: Int,
        authenticationRequired: Boolean = false,
        invalidatedByBiometricEnrollment: Boolean = false
    ): PublicKey {

        lateinit var digest: String

        log.entering()

        try {
            if ((algorithm in supportedAlgorithmsSigning).not()) {
                throw UnsupportedOperationException(
                    String.format(
                        Locale.ENGLISH,
                        "Algorithm %s is not supported",
                        algorithm,
                    )
                )
            }

            val keyStore = KeyStore.getInstance(keystoreType)
            keyStore.load(null)

            if (keyStore.containsAlias(keyName)) {
                keyStore.deleteEntry(keyName)
                log.warn("Existing key `$keyName` deleted")
            }

            if (algorithm == "SHA1withRSA") {
                digest = KeyProperties.DIGEST_SHA1
            } else if (algorithm == "SHA256withRSA") {
                digest = KeyProperties.DIGEST_SHA256
            } else if (algorithm == "SHA512withRSA") {
                digest = KeyProperties.DIGEST_SHA512
            } else {
                digest = KeyProperties.DIGEST_SHA256 // EC
            }

            val keyGenParameterBuilder = KeyGenParameterSpec.Builder(
                keyName,
                purpose,
            )
                .setDigests(digest)
                .setUserAuthenticationRequired(authenticationRequired)
                .setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)

            if (algorithm == "EC") {    // FIDO keys
                keyGenParameterBuilder.setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            } else {    // MFA keys
                // https://groups.google.com/forum/#!msg/android-developers/gDb8cJoSzqc/tJchSd0DDAAJ
                keyGenParameterBuilder.setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                keyGenParameterBuilder.setAlgorithmParameterSpec(
                    RSAKeyGenParameterSpec(
                        keySize,
                        RSAKeyGenParameterSpec.F4
                    )
                )
            }

            // Configure authentication requirements when authenticationRequired is true
            if (authenticationRequired) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // Android 11+ (API 30+): Allow both biometric and device credential
                    // This enables users to authenticate with fingerprint, face, or device PIN/pattern/password
                    keyGenParameterBuilder.setUserAuthenticationParameters(
                        0,  // Timeout of 0 means auth required for every use
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    )
                } else {
                    // Android 10 and below: Use deprecated API
                    @Suppress("deprecation")
                    keyGenParameterBuilder.setUserAuthenticationValidityDurationSeconds(-1)
                }
            }

            KeyPairGenerator.getInstance(
                if (algorithm == "EC") KeyProperties.KEY_ALGORITHM_EC else KeyProperties.KEY_ALGORITHM_RSA,
                keystoreType
            ).let {
                it.initialize(keyGenParameterBuilder.build())
                it.generateKeyPair()

                return keyStore.getCertificate(keyName).publicKey
            }
        } finally {
            log.exiting()
        }
    }

    /**
     * Encrypts and stores a private key using AES-GCM encryption.
     *
     * @param alias The alias of the AES key to use for encryption
     * @param privateKeyBytes The private key bytes to encrypt
     * @return A pair of (encrypted data in Base64, IV in Base64)
     * @throws IllegalStateException if the key with the given alias doesn't exist or is not a SecretKey
     */
    fun encryptAndStorePrivateKey(alias: String, privateKeyBytes: ByteArray): Pair<String, String> {
        val keyStore = KeyStore.getInstance(keystoreType).apply { load(null) }
        
        val entry = keyStore.getEntry(alias, null)
            ?: throw IllegalStateException("Key with alias '$alias' not found in KeyStore")
        
        val secretKey = (entry as? KeyStore.SecretKeyEntry)?.secretKey
            ?: throw IllegalStateException("Key with alias '$alias' is not a SecretKey (found ${entry.javaClass.simpleName})")
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val encrypted = cipher.doFinal(privateKeyBytes)
        val encryptedBase64 = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        val ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP)
        return Pair(encryptedBase64, ivBase64)
    }

    /**
     * Decrypts a private key that was encrypted with [encryptAndStorePrivateKey].
     *
     * @param alias The alias of the AES key to use for decryption
     * @param encryptedBase64 The encrypted data in Base64 format
     * @param ivBase64 The initialization vector in Base64 format
     * @return The decrypted private key bytes
     * @throws IllegalStateException if the key with the given alias doesn't exist or is not a SecretKey
     */
    fun decryptPrivateKey(alias: String, encryptedBase64: String, ivBase64: String): ByteArray {
        val keyStore = KeyStore.getInstance(keystoreType).apply { load(null) }
        
        val entry = keyStore.getEntry(alias, null)
            ?: throw IllegalStateException("Key with alias '$alias' not found in KeyStore")
        
        val secretKey = (entry as? KeyStore.SecretKeyEntry)?.secretKey
            ?: throw IllegalStateException("Key with alias '$alias' is not a SecretKey (found ${entry.javaClass.simpleName})")
        
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        val encryptedBytes = Base64.decode(encryptedBase64, Base64.NO_WRAP)
        return cipher.doFinal(encryptedBytes)
    }

    /**
     * Generates an AES secret key with the specified alias.
     *
     * Attempts to generate a key with StrongBox backing for enhanced security.
     * If StrongBox is not available, automatically falls back to standard KeyStore.
     *
     * Key specifications:
     * - Algorithm: AES
     * - Key Size: 256 bits
     * - Block Mode: GCM (Galois/Counter Mode)
     * - Padding: None (GCM doesn't require padding)
     * - Purpose: Encryption and Decryption
     * - StrongBox: Attempted first, falls back if unavailable
     *
     * @param keyAlias The alias to identify the key in the KeyStore
     * @param useStrongBox Whether to attempt StrongBox backing (default: true)
     * @return The generated SecretKey
     * @throws Exception if key generation fails for reasons other than StrongBox unavailability
     */
    fun generateAESKey(keyAlias: String, useStrongBox: Boolean = true): SecretKey {
        log.entering()

        try {
            return if (useStrongBox) {
                try {
                    log.debug("Attempting to generate AES key with StrongBox backing for alias: $keyAlias")
                    generateAESKeyInternal(keyAlias, isStrongBoxBacked = true)
                } catch (e: Exception) {
                    // Check if the exception is related to StrongBox unavailability
                    if (isStrongBoxException(e)) {
                        log.warn("StrongBox not available, falling back to standard KeyStore", e)
                        generateAESKeyInternal(keyAlias, isStrongBoxBacked = false)
                    } else {
                        log.error("Failed to generate AES key with StrongBox", e)
                        throw e
                    }
                }
            } else {
                log.debug("Generating AES key without StrongBox backing for alias: $keyAlias")
                generateAESKeyInternal(keyAlias, isStrongBoxBacked = false)
            }
        } finally {
            log.exiting()
        }
    }

    /**
     * Internal method to generate an AES key with specified parameters.
     *
     * @param keyAlias The alias to identify the key in the KeyStore
     * @param isStrongBoxBacked Whether to use StrongBox backing
     * @return The generated SecretKey
     */
    private fun generateAESKeyInternal(keyAlias: String, isStrongBoxBacked: Boolean): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            keystoreType
        )

        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(false) // Allow caller-provided IV
            .apply {
                if (isStrongBoxBacked) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()

        keyGenerator.init(keyGenParameterSpec)
        val key = keyGenerator.generateKey()

        log.debug("Successfully generated AES key with alias: $keyAlias, StrongBox: $isStrongBoxBacked")
        return key
    }

    /**
     * Checks if an exception is related to StrongBox unavailability.
     *
     * @param exception The exception to check
     * @return true if the exception indicates StrongBox is unavailable
     */
    private fun isStrongBoxException(exception: Exception): Boolean {
        return when (exception) {
            is StrongBoxUnavailableException -> true
            is java.security.ProviderException -> {
                // Check if the cause or message indicates StrongBox unavailability
                exception.cause is StrongBoxUnavailableException ||
                        exception.message?.contains("StrongBox", ignoreCase = true) == true
            }

            else -> false
        }
    }

    /**
     * Gets or creates an AES key with the specified alias.
     * If the key already exists, it returns the existing key.
     * Otherwise, it generates a new key.
     *
     * @param keyAlias The alias to identify the key
     * @param useStrongBox Whether to attempt StrongBox backing for new keys (default: true)
     * @return The SecretKey (existing or newly generated)
     */
    fun getOrCreateAESKey(keyAlias: String, useStrongBox: Boolean = true): SecretKey {
        log.entering()

        try {
            return getSecretKey(keyAlias) ?: generateAESKey(keyAlias, useStrongBox)
        } finally {
            log.exiting()
        }
    }

    /**
     * Delete a private and public key from the KeyStore.
     *
     * @param keyName  the unique identifier of the key pair
     */
    @Throws(KeyStoreException::class)
    fun deleteKeyPair(keyName: String) {
        log.entering()
        try {
            val keyStore = KeyStore.getInstance(keystoreType)
            keyStore.load(null)
            keyStore.deleteEntry(keyName)
        } finally {
            log.exiting()
        }
    }

    /**
     * Deletes a key (symmetric or asymmetric) from the KeyStore.
     *
     * This unified method handles deletion of any key type (AES, RSA, EC).
     * It checks if the key exists before attempting deletion and provides
     * clear feedback about the operation result.
     *
     * @param keyAlias The alias of the key to delete
     * @return true if the key was successfully deleted, false if key not found or deletion failed
     */
    fun deleteKey(keyAlias: String): Boolean {
        log.entering()

        try {
            val keyStore = KeyStore.getInstance(keystoreType)
            keyStore.load(null)

            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
                log.debug("Successfully deleted key with alias: $keyAlias")
                return true
            } else {
                log.warn("Key with alias $keyAlias not found, nothing to delete")
                return false
            }
        } catch (e: Exception) {
            log.error("Failed to delete key with alias: $keyAlias", e)
            return false
        } finally {
            log.exiting()
        }
    }

    /**
     * Returns the public key retrieved from the keystore.
     *
     * @param keyName  the unique identifier of the key pair
     * @param base64EncodingOption  the encoding format of the public key
     *
     * @return String  encoded representation of the key or `null` if any error
     */
    fun exportPublicKey(keyName: String, base64EncodingOption: Int = Base64.DEFAULT): String? {

        log.entering()

        try {
            var key: String? = null
            KeyStore.getInstance(keystoreType).let { keyStore ->
                keyStore.load(null)
                keyStore.getCertificate(keyName)?.let { certificate ->
                    key = Base64.encodeToString(
                        certificate.publicKey.encoded,
                        base64EncodingOption
                    )
                }
            }

            return key
        } finally {
            log.exiting()
        }
    }

    /**
     * Query the keystore for a matching key name.
     *
     * @param keyName  the unique identifier of the key
     *
     * @return true  if the key exists, false otherwise
     *
     */
    fun exists(keyName: String): Boolean {

        log.entering()

        try {
            KeyStore.getInstance(keystoreType).let { keyStore ->
                keyStore.load(null)
                return keyStore.containsAlias(keyName)
            }
        } finally {
            log.exiting()
        }
    }

    /**
     * Query the Keystore for the private key.
     *
     * @param keyName  the unique identifier of the key pair
     *
     * @return the private key or null if the key is not found
     */
    fun getPrivateKey(keyName: String): PrivateKey? {

        log.entering()

        try {
            var key: PrivateKey? = null
            KeyStore.getInstance(keystoreType).let { keyStore ->
                keyStore.load(null)
                keyStore.getKey(keyName, null)?.let {
                    key = it as PrivateKey
                }
            }

            return key
        } finally {
            log.exiting()
        }
    }

    fun getSecretKey(keyName: String): SecretKey? {

        log.entering()

        try {
            var key: SecretKey? = null
            KeyStore.getInstance(keystoreType).let { keyStore ->
                keyStore.load(null)
                keyStore.getKey(keyName, null)?.let {
                    key = it as SecretKey
                }
            }

            return key
        } finally {
            log.exiting()
        }
    }

    fun getPublicKey(keyName: String): PublicKey? {

        var key: PublicKey? = null
        KeyStore.getInstance(keystoreType).let { keyStore ->
            keyStore.load(null)
            keyStore.getCertificate(keyName)?.let { certificate ->
                key = certificate.publicKey
            }
        }

        return key
    }

    /**
     * Internal helper to perform the actual signing operation.
     * Handles both String and ByteArray data types.
     *
     * @param signature The initialized Signature object
     * @param dataToSign The data to sign (String or ByteArray)
     * @param base64EncodingOption The Base64 encoding option for String results
     * @return The signed data in the same type as input, or null if unsupported type
     */
    @Suppress("UNCHECKED_CAST")
    private fun <T> performSigning(
        signature: Signature,
        dataToSign: T,
        base64EncodingOption: Int
    ): T? {
        return when (dataToSign) {
            is String -> {
                signature.update(dataToSign.toByteArray())
                Base64.encodeToString(signature.sign(), base64EncodingOption) as T
            }

            is ByteArray -> {
                signature.update(dataToSign)
                signature.sign() as T
            }

            else -> {
                log.warn("Unsupported data type for signing: ${dataToSign?.javaClass?.simpleName}")
                null
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T> signData(
        keyName: String,
        algorithm: String,
        dataToSign: T,
        base64EncodingOption: Int = Base64.DEFAULT
    ): T? {

        log.entering()

        try {
            return Signature.getInstance(algorithm).let { signature ->
                getPrivateKey(keyName)?.let { privateKey ->
                    signature.initSign(privateKey)
                    performSigning(signature, dataToSign, base64EncodingOption)
                }
            }
        } finally {
            log.exiting()
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T> signData(
        cryptoObject: BiometricPrompt.CryptoObject,
        dataToSign: T,
        base64EncodingOption: Int = Base64.DEFAULT
    ): T? {

        log.entering()

        try {
            return cryptoObject.signature?.let { signature ->
                performSigning(signature, dataToSign, base64EncodingOption)
            }
        } finally {
            log.exiting()
        }
    }

    /**
     * Creates a [BiometricPrompt.CryptoObject] wrapping a [Signature] initialized with the
     * private key identified by [keyName].  The returned object must be passed to
     * [BiometricPrompt.authenticate] so that the biometric hardware unlocks the key and
     * provides the authenticated [Signature] back in
     * [BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded].
     *
     * This is required when the key was created with
     * [KeyGenParameterSpec.Builder.setUserAuthenticationRequired] set to `true`.
     *
     * @param keyName   the unique identifier of the key pair
     * @param algorithm the signing algorithm (e.g. "SHA256withRSA", "SHA1withRSA")
     *
     * @return a [BiometricPrompt.CryptoObject] ready to be passed to
     *         [BiometricPrompt.authenticate], or `null` if the private key cannot be found
     */
    fun getCryptoObject(keyName: String, algorithm: String): BiometricPrompt.CryptoObject? {

        log.entering()

        try {
            return getPrivateKey(keyName)?.let { privateKey ->
                val signature = Signature.getInstance(algorithm)
                signature.initSign(privateKey)
                BiometricPrompt.CryptoObject(signature)
            }
        } finally {
            log.exiting()
        }
    }

    internal fun hash(input: String, algorithm: String): String {
        return MessageDigest
            .getInstance(algorithm)
            .digest(input.toByteArray())
            .fold("") { str, it -> str + "%02x".format(it) }
    }

    internal fun hash(input: ByteArray, algorithm: String): String {
        return MessageDigest
            .getInstance(algorithm)
            .digest(input)
            .fold("") { str, it -> str + "%02x".format(it) }
    }
}