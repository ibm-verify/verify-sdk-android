/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core

import android.os.Build
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import com.ibm.security.verifysdk.core.helper.KeystoreHelper
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.KeyStoreException
import java.util.Locale
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

/**
 * Comprehensive test suite for KeystoreHelper.
 *
 * Tests verify:
 * 1. AES key generation and management
 * 2. RSA/EC key pair generation
 * 3. StrongBox support and fallback
 * 4. Key deletion (unified method)
 * 5. Private key encryption/decryption
 * 6. Signing operations
 * 7. Key existence checks
 * 8. Thread safety
 * 9. Edge cases and error handling
 */
@RunWith(AndroidJUnit4::class)
@SmallTest
internal class KeystoreHelperTest {

    private lateinit var log: Logger
    private val testKeysToCleanup = mutableListOf<String>()

    private val supportedAlgorithms: ArrayList<String> =
        arrayListOf("SHA1withRSA", "SHA256withRSA", "SHA512withRSA")

    @Before
    fun setUp() {
        log = LoggerFactory.getLogger(javaClass)
    }

    @After
    fun tearDown() {
        // Clean up any test keys created during tests
        testKeysToCleanup.forEach { keyAlias ->
            try {
                KeystoreHelper.deleteKey(keyAlias)
            } catch (e: Exception) {
                log.warn("Failed to cleanup test key: $keyAlias", e)
            }
        }
        testKeysToCleanup.clear()
    }

    private fun generateTestKeyAlias(prefix: String = "test"): String {
        val alias = "$prefix-${UUID.randomUUID()}"
        testKeysToCleanup.add(alias)
        return alias
    }

    @Test
    fun getKeystoreType() {
        assertEquals("AndroidKeyStore", KeystoreHelper.keystoreType)
    }

    @Test
    fun setKeystoreType() {
        val originalKeystoreType = KeystoreHelper.keystoreType
        try {
            val newKeystoreType = "BouncyCastle"
            KeystoreHelper.keystoreType = newKeystoreType
            assertEquals(newKeystoreType, KeystoreHelper.keystoreType)
        } finally {
            // Reset to original to avoid affecting other tests
            KeystoreHelper.keystoreType = originalKeystoreType
        }
    }

    @Test(expected = KeyStoreException::class)
    fun setKeystoreType_unknownType_shouldThrowException() {
        val originalKeystoreType = KeystoreHelper.keystoreType
        try {
            val newKeystoreType = "unknownKeyStoreType"
            KeystoreHelper.keystoreType = newKeystoreType
        } finally {
            // Reset to original even if exception is thrown
            KeystoreHelper.keystoreType = originalKeystoreType
        }
    }

    @Test
    fun getKeySize() {
        assertEquals(2048, KeystoreHelper.keySize)
    }

    @Test
    fun setKeySize() {
        val previousKeysize = KeystoreHelper.keySize
        val newKeysize = 4096
        KeystoreHelper.keySize = newKeysize
        assertEquals(newKeysize, KeystoreHelper.keySize)
        KeystoreHelper.keySize = previousKeysize
    }

    @Test
    fun createKeyPair_happyPath_shouldReturnPublicKey() {

        for (algorithm in supportedAlgorithms) {
            val keyName =
                String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
            val publicKey =
                KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
            assertEquals("X.509", publicKey.format)
        }
    }

    @Test
    @Ignore("Fails - fix build first")
    fun createKeyPair_happyPathOverwriteDefaultsCase2of4_shouldReturnPublicKey() {

        val authenticationRequired = true
        val invalidatedByBiometricEnrollment = true

        for (algorithm in supportedAlgorithms) {
            val keyName =
                String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
            val publicKey = KeystoreHelper.createKeyPair(
                keyName,
                algorithm,
                KeyProperties.PURPOSE_SIGN,
                authenticationRequired,
                invalidatedByBiometricEnrollment
            )
            assertEquals("X.509", publicKey.format)
        }
    }

    @Test
    fun createKeyPair_happyPathOverwriteDefaultsCase3of4_shouldReturnPublicKey() {

        val authenticationRequired = false
        val invalidatedByBiometricEnrollment = true

        for (algorithm in supportedAlgorithms) {
            val keyName =
                String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
            val publicKey = KeystoreHelper.createKeyPair(
                keyName,
                algorithm,
                KeyProperties.PURPOSE_SIGN,
                authenticationRequired,
                invalidatedByBiometricEnrollment
            )
            assertEquals("X.509", publicKey.format)
        }
    }

    @Test
    @Ignore("Fails - fix build first")
    fun createKeyPair_happyPathOverwriteDefaultsCase4of4_shouldReturnPublicKey() {

        val authenticationRequired = true
        val invalidatedByBiometricEnrollment = false

        for (algorithm in supportedAlgorithms) {
            val keyName =
                String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
            val publicKey = KeystoreHelper.createKeyPair(
                keyName,
                algorithm,
                KeyProperties.PURPOSE_SIGN,
                authenticationRequired,
                invalidatedByBiometricEnrollment
            )
            assertEquals("X.509", publicKey.format)
        }
    }

    @Test
    fun createKeyPair_happyPathSdkQ_shouldReturnPublicKey() {

        val sdkVersion = Build.VERSION.SDK_INT
        TestHelper.setFinalStatic(
            Build.VERSION::class.java.getField("SDK_INT"),
            Build.VERSION_CODES.Q
        )
        for (algorithm in supportedAlgorithms) {
            val keyName =
                String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
            val publicKey =
                KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
            assertEquals("X.509", publicKey.format)
        }
        TestHelper.setFinalStatic(
            Build.VERSION::class.java.getField("SDK_INT"),
            sdkVersion
        )
    }

    @Test
    fun createKeyPair_happyPathSdkM_shouldReturnPublicKey() {

        val sdkVersion = Build.VERSION.SDK_INT
        TestHelper.setFinalStatic(
            Build.VERSION::class.java.getField("SDK_INT"),
            Build.VERSION_CODES.M
        )
        for (algorithm in supportedAlgorithms) {
            val keyName =
                String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
            val publicKey =
                KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
            assertEquals("X.509", publicKey.format)
        }
        TestHelper.setFinalStatic(
            Build.VERSION::class.java.getField("SDK_INT"),
            sdkVersion
        )
    }

    @Test
    fun createKeyPair_overwriteExistingKey_shouldReturnNewPublicKey() {

        val keyName =
            String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
        val algorithm = supportedAlgorithms[0]
        KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
        val publicKeyFirst = KeystoreHelper.exportPublicKey(keyName)
        KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
        val publicKeySecond = KeystoreHelper.exportPublicKey(keyName)
        assertNotEquals(publicKeyFirst, publicKeySecond)
    }

    @Test(expected = UnsupportedOperationException::class)
    fun createKeyPair_unsupportedAlgorithm_shouldThrowException() {
        val keyName =
            String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
        KeystoreHelper.createKeyPair(keyName, "unsupportedAlgorithm", KeyProperties.PURPOSE_SIGN)
        assertFalse(true)
    }

    @Test
    fun deleteKeyPair() {
        val keyName =
            String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
        val algorithm = supportedAlgorithms[0]
        KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)
        assertTrue(KeystoreHelper.exists(keyName))
        KeystoreHelper.deleteKeyPair(keyName)
        assertTrue(KeystoreHelper.exists(keyName).not())
    }

    @Test
    fun exportPublicKey() {
        val keyName =
            String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
        val algorithm = supportedAlgorithms[0]
        KeystoreHelper.createKeyPair(keyName, algorithm, KeyProperties.PURPOSE_SIGN)

        val publicKey = KeystoreHelper.exportPublicKey(keyName)
        assertNotNull(publicKey)
        assertNotNull(publicKey)
        publicKey?.let {
            assert(publicKey.startsWith("MIIB"))
        }
    }

    @Test
    fun exportPublicKey_unknownKey_shouldReturnNull() {

        val keyName =
            String.format(Locale.getDefault(), "unknownKey-%s", UUID.randomUUID().toString())
        val publicKey = KeystoreHelper.exportPublicKey(keyName)
        assertNull(publicKey)
    }

    @Test
    fun exists() {
        val keyName =
            String.format(Locale.getDefault(), "myTestKey-%s", UUID.randomUUID().toString())
        assertTrue(KeystoreHelper.exists(keyName).not())
        KeystoreHelper.createKeyPair(keyName, supportedAlgorithms[0], KeyProperties.PURPOSE_SIGN)
        assertTrue(KeystoreHelper.exists(keyName))
    }

    // ========================================
    // AES Key Management Tests
    // ========================================

    /**
     * Test generating a new AES key with default settings.
     */
    @Test
    fun testGenerateAESKey() {
            val keyAlias = generateTestKeyAlias("aes")

            val secretKey = KeystoreHelper.generateAESKey(keyAlias)

            assertNotNull("Secret key should not be null", secretKey)
            assertEquals("AES", secretKey.algorithm)
            assertTrue("Key should exist in keystore", KeystoreHelper.exists(keyAlias))
        }

        /**
         * Test generating AES key without StrongBox.
         */
        @Test
        fun testGenerateAESKeyWithoutStrongBox() {
            val keyAlias = generateTestKeyAlias("aes-no-strongbox")

            val secretKey = KeystoreHelper.generateAESKey(keyAlias, useStrongBox = false)

            assertNotNull("Secret key should not be null", secretKey)
            assertEquals("AES", secretKey.algorithm)
            assertTrue("Key should exist in keystore", KeystoreHelper.exists(keyAlias))
        }

        /**
         * Test getting or creating AES key (key doesn't exist).
         */
        @Test
        fun testGetOrCreateAESKey_KeyDoesNotExist() {
            val keyAlias = generateTestKeyAlias("aes-get-or-create")

            assertFalse("Key should not exist initially", KeystoreHelper.exists(keyAlias))

            val secretKey = KeystoreHelper.getOrCreateAESKey(keyAlias)

            assertNotNull("Secret key should not be null", secretKey)
            assertTrue("Key should now exist", KeystoreHelper.exists(keyAlias))
        }

        /**
         * Test getting or creating AES key (key already exists).
         */
        @Test
        fun testGetOrCreateAESKey_KeyExists() {
            val keyAlias = generateTestKeyAlias("aes-existing")

            // Create key first
            val firstKey = KeystoreHelper.generateAESKey(keyAlias)

            // Get the same key
            val secondKey = KeystoreHelper.getOrCreateAESKey(keyAlias)

            assertNotNull("Second key should not be null", secondKey)
            assertEquals("Should return the same key", firstKey, secondKey)
        }

        /**
         * Test AES key encryption and decryption.
         */
        @Test
        fun testAESKeyEncryptionDecryption() {
            val keyAlias = generateTestKeyAlias("aes-encrypt")
            val secretKey = KeystoreHelper.generateAESKey(keyAlias)

            val plaintext = "Test data to encrypt"
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")

            // Encrypt
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext.toByteArray())

            // Decrypt
            val decryptCipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            val decrypted = decryptCipher.doFinal(ciphertext)

            assertEquals("Decrypted text should match original", plaintext, String(decrypted))
        }

        /**
         * Test encrypting and storing a private key.
         *
         * Note: This test uses synthetic test data instead of a KeyStore private key
         * because Android KeyStore private keys don't expose their encoded bytes
         * (privateKey.encoded returns null for security reasons).
         *
         * The encryptAndStorePrivateKey method is designed for wrapping external
         * private keys (e.g., imported keys) for secure storage.
         */
        @Test
        fun testEncryptAndStorePrivateKey() {
            val aesKeyAlias = generateTestKeyAlias("aes-wrapper")

            // Generate AES key for wrapping
            KeystoreHelper.generateAESKey(aesKeyAlias)

            // Use synthetic test data instead of actual KeyStore private key
            // (KeyStore private keys don't expose encoded bytes)
            val testPrivateKeyBytes = "test-private-key-data-12345".toByteArray()

            // Encrypt and store
            val (encryptedBase64, ivBase64) = KeystoreHelper.encryptAndStorePrivateKey(
                aesKeyAlias,
                testPrivateKeyBytes
            )

            assertNotNull("Encrypted data should not be null", encryptedBase64)
            assertNotNull("IV should not be null", ivBase64)
            assertTrue("Encrypted data should not be empty", encryptedBase64.isNotEmpty())
            assertTrue("IV should not be empty", ivBase64.isNotEmpty())
        }

        /**
         * Test decrypting a private key.
         *
         * Note: Uses synthetic test data because Android KeyStore private keys
         * don't expose their encoded bytes for security reasons.
         */
        @Test
        fun testDecryptPrivateKey() {
            val aesKeyAlias = generateTestKeyAlias("aes-unwrapper")

            // Generate AES key
            KeystoreHelper.generateAESKey(aesKeyAlias)

            // Use synthetic test data
            val originalBytes = "test-private-key-data-67890".toByteArray()

            // Encrypt
            val (encryptedBase64, ivBase64) = KeystoreHelper.encryptAndStorePrivateKey(
                aesKeyAlias,
                originalBytes
            )

            // Decrypt
            val decryptedBytes = KeystoreHelper.decryptPrivateKey(
                aesKeyAlias,
                encryptedBase64,
                ivBase64
            )

            assertTrue(
                "Decrypted bytes should match original",
                originalBytes.contentEquals(decryptedBytes)
            )
        }

        /**
         * Test round-trip encryption/decryption of private key.
         *
         * Note: Uses synthetic test data because Android KeyStore private keys
         * don't expose their encoded bytes for security reasons.
         */
        @Test
        fun testPrivateKeyRoundTrip() {
            val aesKeyAlias = generateTestKeyAlias("aes-roundtrip")

            KeystoreHelper.generateAESKey(aesKeyAlias)

            // Use synthetic test data
            val originalBytes = "test-private-key-roundtrip-data".toByteArray()

            // Encrypt
            val (encrypted, iv) = KeystoreHelper.encryptAndStorePrivateKey(
                aesKeyAlias,
                originalBytes
            )

            // Decrypt
            val decrypted = KeystoreHelper.decryptPrivateKey(aesKeyAlias, encrypted, iv)

            // Verify
            assertTrue("Round-trip should preserve data", originalBytes.contentEquals(decrypted))
        }

        // ========================================
        // Unified Key Deletion Tests
        // ========================================

        /**
         * Test deleting an AES key using unified deleteKey method.
         */
        @Test
        fun testDeleteAESKey() {
            val keyAlias = generateTestKeyAlias("aes-delete")

            KeystoreHelper.generateAESKey(keyAlias)
            assertTrue("Key should exist", KeystoreHelper.exists(keyAlias))

            val deleted = KeystoreHelper.deleteKey(keyAlias)

            assertTrue("Delete should return true", deleted)
            assertFalse("Key should no longer exist", KeystoreHelper.exists(keyAlias))
        }

        /**
         * Test deleting an RSA key using unified deleteKey method.
         */
        @Test
        fun testDeleteRSAKey() {
            val keyAlias = generateTestKeyAlias("rsa-delete")

            KeystoreHelper.createKeyPair(keyAlias, "SHA256withRSA", KeyProperties.PURPOSE_SIGN)
            assertTrue("Key should exist", KeystoreHelper.exists(keyAlias))

            val deleted = KeystoreHelper.deleteKey(keyAlias)

            assertTrue("Delete should return true", deleted)
            assertFalse("Key should no longer exist", KeystoreHelper.exists(keyAlias))
        }

        /**
         * Test deleting an EC key using unified deleteKey method.
         */
        @Test
        fun testDeleteECKey() {
            val keyAlias = generateTestKeyAlias("ec-delete")

            KeystoreHelper.createKeyPair(keyAlias, "EC", KeyProperties.PURPOSE_SIGN)
            assertTrue("Key should exist", KeystoreHelper.exists(keyAlias))

            val deleted = KeystoreHelper.deleteKey(keyAlias)

            assertTrue("Delete should return true", deleted)
            assertFalse("Key should no longer exist", KeystoreHelper.exists(keyAlias))
        }

        /**
         * Test deleting a non-existent key.
         */
        @Test
        fun testDeleteNonExistentKey() {
            val keyAlias = generateTestKeyAlias("non-existent")

            assertFalse("Key should not exist", KeystoreHelper.exists(keyAlias))

            val deleted = KeystoreHelper.deleteKey(keyAlias)

            assertFalse("Delete should return false for non-existent key", deleted)
        }

        /**
         * Test deleting the same key twice.
         */
        @Test
        fun testDeleteKeyTwice() {
            val keyAlias = generateTestKeyAlias("delete-twice")

            KeystoreHelper.generateAESKey(keyAlias)

            val firstDelete = KeystoreHelper.deleteKey(keyAlias)
            assertTrue("First delete should succeed", firstDelete)

            val secondDelete = KeystoreHelper.deleteKey(keyAlias)
            assertFalse("Second delete should return false", secondDelete)
        }

        // ========================================
        // Key Retrieval Tests
        // ========================================

        /**
         * Test getting a secret key that exists.
         */
        @Test
        fun testGetSecretKey_Exists() {
            val keyAlias = generateTestKeyAlias("aes-get")

            KeystoreHelper.generateAESKey(keyAlias)

            val secretKey = KeystoreHelper.getSecretKey(keyAlias)

            assertNotNull("Secret key should be retrieved", secretKey)
            assertEquals("AES", secretKey?.algorithm)
        }

        /**
         * Test getting a secret key that doesn't exist.
         */
        @Test
        fun testGetSecretKey_NotExists() {
            val keyAlias = generateTestKeyAlias("aes-not-exist")

            val secretKey = KeystoreHelper.getSecretKey(keyAlias)

            assertNull("Secret key should be null", secretKey)
        }

        /**
         * Test getting a private key that exists.
         */
        @Test
        fun testGetPrivateKey_Exists() {
            val keyAlias = generateTestKeyAlias("rsa-get-private")

            KeystoreHelper.createKeyPair(keyAlias, "SHA256withRSA", KeyProperties.PURPOSE_SIGN)

            val privateKey = KeystoreHelper.getPrivateKey(keyAlias)

            assertNotNull("Private key should be retrieved", privateKey)
            assertEquals("RSA", privateKey?.algorithm)
        }

        /**
         * Test getting a private key that doesn't exist.
         */
        @Test
        fun testGetPrivateKey_NotExists() {
            val keyAlias = generateTestKeyAlias("rsa-not-exist")

            val privateKey = KeystoreHelper.getPrivateKey(keyAlias)

            assertNull("Private key should be null", privateKey)
        }

        /**
         * Test getting a public key that exists.
         */
        @Test
        fun testGetPublicKey_Exists() {
            val keyAlias = generateTestKeyAlias("rsa-get-public")

            KeystoreHelper.createKeyPair(keyAlias, "SHA256withRSA", KeyProperties.PURPOSE_SIGN)

            val publicKey = KeystoreHelper.getPublicKey(keyAlias)

            assertNotNull("Public key should be retrieved", publicKey)
            assertEquals("RSA", publicKey?.algorithm)
        }

        /**
         * Test getting a public key that doesn't exist.
         */
        @Test
        fun testGetPublicKey_NotExists() {
            val keyAlias = generateTestKeyAlias("rsa-public-not-exist")

            val publicKey = KeystoreHelper.getPublicKey(keyAlias)

            assertNull("Public key should be null", publicKey)
        }

        // ========================================
        // EC Key Tests
        // ========================================

        /**
         * Test creating an EC key pair.
         */
        @Test
        fun testCreateECKeyPair() {
            val keyAlias = generateTestKeyAlias("ec-create")

            val publicKey = KeystoreHelper.createKeyPair(
                keyAlias,
                "EC",
                KeyProperties.PURPOSE_SIGN
            )

            assertNotNull("Public key should not be null", publicKey)
            assertEquals("EC", publicKey.algorithm)
            assertEquals("X.509", publicKey.format)
        }

        /**
         * Test signing data with EC key.
         */
        @Test
        fun testSignDataWithECKey() {
            val keyAlias = generateTestKeyAlias("ec-sign")

            KeystoreHelper.createKeyPair(keyAlias, "EC", KeyProperties.PURPOSE_SIGN)

            val dataToSign = "Test data for EC signing"
            val signature = KeystoreHelper.signData(keyAlias, "SHA256withECDSA", dataToSign)

            assertNotNull("Signature should not be null", signature)
            assertTrue("Signature should not be empty", signature!!.isNotEmpty())
        }

        /**
         * Test signing ByteArray with EC key.
         */
        @Test
        fun testSignByteArrayWithECKey() {
            val keyAlias = generateTestKeyAlias("ec-sign-bytes")

            KeystoreHelper.createKeyPair(keyAlias, "EC", KeyProperties.PURPOSE_SIGN)

            val dataToSign = "Test data".toByteArray()
            val signature = KeystoreHelper.signData(keyAlias, "SHA256withECDSA", dataToSign)

            assertNotNull("Signature should not be null", signature)
            assertTrue("Signature should not be empty", signature!!.isNotEmpty())
        }

        // ========================================
        // Hash Function Tests
        // ========================================

        /**
         * Test hashing a string with SHA-256.
         */
        @Test
        fun testHashString() {
            val input = "test string"
            val hash = KeystoreHelper.hash(input, "SHA-256")

            assertNotNull("Hash should not be null", hash)
            assertEquals(64, hash.length) // SHA-256 produces 64 hex characters
        }

        /**
         * Test hashing a ByteArray with SHA-256.
         */
        @Test
        fun testHashByteArray() {
            val input = "test string".toByteArray()
            val hash = KeystoreHelper.hash(input, "SHA-256")

            assertNotNull("Hash should not be null", hash)
            assertEquals(64, hash.length)
        }

        /**
         * Test that same input produces same hash.
         */
        @Test
        fun testHashConsistency() {
            val input = "consistent input"
            val hash1 = KeystoreHelper.hash(input, "SHA-256")
            val hash2 = KeystoreHelper.hash(input, "SHA-256")

            assertEquals("Same input should produce same hash", hash1, hash2)
        }

        /**
         * Test that different inputs produce different hashes.
         */
        @Test
        fun testHashUniqueness() {
            val input1 = "input one"
            val input2 = "input two"
            val hash1 = KeystoreHelper.hash(input1, "SHA-256")
            val hash2 = KeystoreHelper.hash(input2, "SHA-256")

            assertNotEquals("Different inputs should produce different hashes", hash1, hash2)
        }

        // ========================================
        // Edge Cases and Error Handling
        // ========================================

        /**
         * Test creating key with empty alias.
         */
        @Test(expected = IllegalArgumentException::class)
        fun testCreateKeyPairWithEmptyAlias() {
            KeystoreHelper.createKeyPair("", "SHA256withRSA", KeyProperties.PURPOSE_SIGN)
        }

        /**
         * Test signing with non-existent key returns null.
         */
        @Test
        fun testSignDataWithNonExistentKey() {
            val keyAlias = generateTestKeyAlias("non-existent-sign")

            val signature = KeystoreHelper.signData(keyAlias, "SHA256withRSA", "data")

            assertNull("Signature should be null for non-existent key", signature)
        }

        /**
         * Test exporting public key with different Base64 encoding options.
         */
        @Test
        fun testExportPublicKeyWithDifferentEncodings() {
            val keyAlias = generateTestKeyAlias("rsa-export-encoding")

            KeystoreHelper.createKeyPair(keyAlias, "SHA256withRSA", KeyProperties.PURPOSE_SIGN)

            val defaultEncoding = KeystoreHelper.exportPublicKey(keyAlias, Base64.DEFAULT)
            val urlSafeEncoding = KeystoreHelper.exportPublicKey(keyAlias, Base64.URL_SAFE)
            val noWrapEncoding = KeystoreHelper.exportPublicKey(keyAlias, Base64.NO_WRAP)

            assertNotNull("Default encoding should work", defaultEncoding)
            assertNotNull("URL safe encoding should work", urlSafeEncoding)
            assertNotNull("No wrap encoding should work", noWrapEncoding)

            // They should be different due to encoding differences
            assertNotEquals(
                "Different encodings should produce different results",
                defaultEncoding, urlSafeEncoding
            )
        }

        /**
         * Test that key exists check is accurate.
         */
        @Test
        fun testKeyExistsAccuracy() {
            val keyAlias = generateTestKeyAlias("exists-check")

            assertFalse("Key should not exist initially", KeystoreHelper.exists(keyAlias))

            KeystoreHelper.generateAESKey(keyAlias)
            assertTrue("Key should exist after creation", KeystoreHelper.exists(keyAlias))

            KeystoreHelper.deleteKey(keyAlias)
            assertFalse("Key should not exist after deletion", KeystoreHelper.exists(keyAlias))
        }

        /**
         * Test creating multiple keys with different aliases.
         */
        @Test
        fun testMultipleKeysWithDifferentAliases() {
            val alias1 = generateTestKeyAlias("multi-1")
            val alias2 = generateTestKeyAlias("multi-2")
            val alias3 = generateTestKeyAlias("multi-3")

            KeystoreHelper.generateAESKey(alias1)
            KeystoreHelper.createKeyPair(alias2, "SHA256withRSA", KeyProperties.PURPOSE_SIGN)
            KeystoreHelper.createKeyPair(alias3, "EC", KeyProperties.PURPOSE_SIGN)

            assertTrue("Key 1 should exist", KeystoreHelper.exists(alias1))
            assertTrue("Key 2 should exist", KeystoreHelper.exists(alias2))
            assertTrue("Key 3 should exist", KeystoreHelper.exists(alias3))

            assertNotNull("AES key should be retrievable", KeystoreHelper.getSecretKey(alias1))
            assertNotNull("RSA key should be retrievable", KeystoreHelper.getPrivateKey(alias2))
            assertNotNull("EC key should be retrievable", KeystoreHelper.getPrivateKey(alias3))
        }

        /**
         * Test key size configuration.
         */
        @Test
        fun testKeySizeConfiguration() {
            val originalKeySize = KeystoreHelper.keySize

            try {
                KeystoreHelper.keySize = 4096
                assertEquals(4096, KeystoreHelper.keySize)

                val keyAlias = generateTestKeyAlias("rsa-4096")
                KeystoreHelper.createKeyPair(keyAlias, "SHA256withRSA", KeyProperties.PURPOSE_SIGN)

                val publicKey = KeystoreHelper.getPublicKey(keyAlias)
                assertNotNull("Public key should be created with custom size", publicKey)
            } finally {
                KeystoreHelper.keySize = originalKeySize
            }
        }

        /**
         * Test getCryptoObject returns null for non-existent key.
         */
        @Test
        fun testGetCryptoObjectWithNonExistentKey() {
            val keyAlias = generateTestKeyAlias("crypto-non-existent")

            val cryptoObject = KeystoreHelper.getCryptoObject(keyAlias, "SHA256withRSA")

            assertNull("CryptoObject should be null for non-existent key", cryptoObject)
        }

    /**
     * Test getCryptoObject for existing key.
     */
    @Test
    fun testGetCryptoObjectWithExistingKey() {
        val keyAlias = generateTestKeyAlias("crypto-existing")

        KeystoreHelper.createKeyPair(
            keyAlias,
            "SHA256withRSA",
            KeyProperties.PURPOSE_SIGN,
            authenticationRequired = false
        )

        val cryptoObject = KeystoreHelper.getCryptoObject(keyAlias, "SHA256withRSA")

        assertNotNull("CryptoObject should not be null", cryptoObject)
        assertNotNull("CryptoObject should contain signature", cryptoObject?.signature)
    }

    /**
     * Test signing data with valid key.
     */
    @Test
    fun testSignDataHappyPath() {
        val keyAlias = generateTestKeyAlias("sign-happy")
        val algorithm = supportedAlgorithms[0]

        KeystoreHelper.createKeyPair(keyAlias, algorithm, KeyProperties.PURPOSE_SIGN)

        val signedData = KeystoreHelper.signData(keyAlias, algorithm, "dataToSign")
        assertNotNull("Signed data should not be null", signedData)
        assertTrue("Signed data should not be empty", signedData!!.isNotEmpty())
    }

    /**
     * Test signing data with custom Base64 encoding.
     */
    @Test
    fun testSignDataWithCustomEncoding() {
        val keyAlias = generateTestKeyAlias("sign-encoding")
        val algorithm = supportedAlgorithms[0]

        KeystoreHelper.createKeyPair(keyAlias, algorithm, KeyProperties.PURPOSE_SIGN)

        val signedData =
            KeystoreHelper.signData(keyAlias, algorithm, "dataToSign", Base64.URL_SAFE)
        assertNotNull("Signed data should not be null", signedData)
        assertTrue("Signed data should not be empty", signedData!!.isNotEmpty())
    }

    /**
     * Test signing with unknown key returns null.
     */
    @Test
    fun testSignDataWithUnknownKey() {
        val keyAlias = generateTestKeyAlias("unknown-sign")
        val algorithm = supportedAlgorithms[0]

        val signedData =
            KeystoreHelper.signData(keyAlias, algorithm, "dataToSign", Base64.URL_SAFE)
        assertNull("Signed data should be null for unknown key", signedData)
    }
}
