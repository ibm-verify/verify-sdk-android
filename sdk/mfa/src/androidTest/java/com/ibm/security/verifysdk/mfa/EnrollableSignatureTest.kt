/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EnrollableSignatureTest {

    @Test
    fun constructor_withAllParameters_shouldCreateInstance() {
        // Given
        val biometricAuth = true
        val algorithm = HashAlgorithmType.SHA256
        val authenticatorId = "auth-123"
        val enrollableType = EnrollableType.FINGERPRINT

        // When
        val signature = EnrollableSignature(
            biometricAuthentication = biometricAuth,
            algorithmType = algorithm,
            authenticatorId = authenticatorId,
            enrollableType = enrollableType
        )

        // Then
        assertTrue(signature.biometricAuthentication)
        assertEquals(algorithm, signature.algorithmType)
        assertEquals(authenticatorId, signature.authenticatorId)
        assertEquals(enrollableType, signature.enrollableType)
    }

    @Test
    fun constructor_withBiometricAuthFalse_shouldCreateInstance() {
        // When
        val signature = EnrollableSignature(
            biometricAuthentication = false,
            algorithmType = HashAlgorithmType.SHA1,
            authenticatorId = "auth-456",
            enrollableType = EnrollableType.TOTP
        )

        // Then
        assertFalse(signature.biometricAuthentication)
    }

    @Test
    fun constructor_withTOTPType_shouldCreateInstance() {
        // When
        val signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "auth-789",
            enrollableType = EnrollableType.TOTP
        )

        // Then
        assertEquals(EnrollableType.TOTP, signature.enrollableType)
    }

    @Test
    fun constructor_withHOTPType_shouldCreateInstance() {
        // When
        val signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "auth-101",
            enrollableType = EnrollableType.HOTP
        )

        // Then
        assertEquals(EnrollableType.HOTP, signature.enrollableType)
    }

    @Test
    fun constructor_withFaceType_shouldCreateInstance() {
        // When
        val signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA384,
            authenticatorId = "auth-102",
            enrollableType = EnrollableType.FACE
        )

        // Then
        assertEquals(EnrollableType.FACE, signature.enrollableType)
    }

    @Test
    fun constructor_withFingerprintType_shouldCreateInstance() {
        // When
        val signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA512,
            authenticatorId = "auth-103",
            enrollableType = EnrollableType.FINGERPRINT
        )

        // Then
        assertEquals(EnrollableType.FINGERPRINT, signature.enrollableType)
    }

    @Test
    fun constructor_withUserPresenceType_shouldCreateInstance() {
        // When
        val signature = EnrollableSignature(
            biometricAuthentication = false,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "auth-104",
            enrollableType = EnrollableType.USER_PRESENCE
        )

        // Then
        assertEquals(EnrollableType.USER_PRESENCE, signature.enrollableType)
    }

    @Test
    fun constructor_withAllHashAlgorithms_shouldCreateInstances() {
        // Test SHA1
        val sha1Signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA1,
            authenticatorId = "auth-sha1",
            enrollableType = EnrollableType.TOTP
        )
        assertEquals(HashAlgorithmType.SHA1, sha1Signature.algorithmType)

        // Test SHA256
        val sha256Signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "auth-sha256",
            enrollableType = EnrollableType.TOTP
        )
        assertEquals(HashAlgorithmType.SHA256, sha256Signature.algorithmType)

        // Test SHA384
        val sha384Signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA384,
            authenticatorId = "auth-sha384",
            enrollableType = EnrollableType.TOTP
        )
        assertEquals(HashAlgorithmType.SHA384, sha384Signature.algorithmType)

        // Test SHA512
        val sha512Signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA512,
            authenticatorId = "auth-sha512",
            enrollableType = EnrollableType.TOTP
        )
        assertEquals(HashAlgorithmType.SHA512, sha512Signature.algorithmType)
    }

    @Test
    fun serialization_shouldSerializeAndDeserialize() {
        // Given
        val signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-auth-id",
            enrollableType = EnrollableType.FINGERPRINT
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(signature)
        val deserialized = json.decodeFromString<EnrollableSignature>(serialized)

        // Then
        assertEquals(signature.biometricAuthentication, deserialized.biometricAuthentication)
        assertEquals(signature.algorithmType, deserialized.algorithmType)
        assertEquals(signature.authenticatorId, deserialized.authenticatorId)
        assertEquals(signature.enrollableType, deserialized.enrollableType)
    }

    @Test
    fun deserialization_fromJsonString_shouldCreateInstance() {
        // Given
        val jsonString = """
            {
                "biometricAuthentication": true,
                "algorithmType": "SHA256",
                "authenticatorId": "json-auth-id",
                "enrollableType": "FINGERPRINT"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val signature = json.decodeFromString<EnrollableSignature>(jsonString)

        // Then
        assertTrue(signature.biometricAuthentication)
        assertEquals(HashAlgorithmType.SHA256, signature.algorithmType)
        assertEquals("json-auth-id", signature.authenticatorId)
        assertEquals(EnrollableType.FINGERPRINT, signature.enrollableType)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "original-id",
            enrollableType = EnrollableType.FACE
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.biometricAuthentication, copy.biometricAuthentication)
        assertEquals(original.algorithmType, copy.algorithmType)
        assertEquals(original.authenticatorId, copy.authenticatorId)
        assertEquals(original.enrollableType, copy.enrollableType)
    }

    @Test
    fun copy_withModifiedBiometricAuth_shouldUpdateOnlyBiometricAuth() {
        // Given
        val original = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-id",
            enrollableType = EnrollableType.TOTP
        )

        // When
        val modified = original.copy(biometricAuthentication = false)

        // Then
        assertFalse(modified.biometricAuthentication)
        assertEquals(original.algorithmType, modified.algorithmType)
        assertEquals(original.authenticatorId, modified.authenticatorId)
        assertEquals(original.enrollableType, modified.enrollableType)
    }

    @Test
    fun copy_withModifiedAlgorithmType_shouldUpdateOnlyAlgorithmType() {
        // Given
        val original = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-id",
            enrollableType = EnrollableType.TOTP
        )

        // When
        val modified = original.copy(algorithmType = HashAlgorithmType.SHA512)

        // Then
        assertEquals(original.biometricAuthentication, modified.biometricAuthentication)
        assertEquals(HashAlgorithmType.SHA512, modified.algorithmType)
        assertEquals(original.authenticatorId, modified.authenticatorId)
        assertEquals(original.enrollableType, modified.enrollableType)
    }

    @Test
    fun copy_withModifiedAuthenticatorId_shouldUpdateOnlyAuthenticatorId() {
        // Given
        val original = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "original-id",
            enrollableType = EnrollableType.TOTP
        )

        // When
        val modified = original.copy(authenticatorId = "new-id")

        // Then
        assertEquals(original.biometricAuthentication, modified.biometricAuthentication)
        assertEquals(original.algorithmType, modified.algorithmType)
        assertEquals("new-id", modified.authenticatorId)
        assertEquals(original.enrollableType, modified.enrollableType)
    }

    @Test
    fun copy_withModifiedEnrollableType_shouldUpdateOnlyEnrollableType() {
        // Given
        val original = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-id",
            enrollableType = EnrollableType.TOTP
        )

        // When
        val modified = original.copy(enrollableType = EnrollableType.HOTP)

        // Then
        assertEquals(original.biometricAuthentication, modified.biometricAuthentication)
        assertEquals(original.algorithmType, modified.algorithmType)
        assertEquals(original.authenticatorId, modified.authenticatorId)
        assertEquals(EnrollableType.HOTP, modified.enrollableType)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val signature1 = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-id",
            enrollableType = EnrollableType.FINGERPRINT
        )
        val signature2 = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-id",
            enrollableType = EnrollableType.FINGERPRINT
        )

        // Then
        assertEquals(signature1, signature2)
    }

    @Test
    fun equals_withDifferentBiometricAuth_shouldReturnFalse() {
        // Given
        val signature1 = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-id",
            enrollableType = EnrollableType.FINGERPRINT
        )
        val signature2 = EnrollableSignature(
            biometricAuthentication = false,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-id",
            enrollableType = EnrollableType.FINGERPRINT
        )

        // Then
        assertNotEquals(signature1, signature2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val signature1 = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-id",
            enrollableType = EnrollableType.FINGERPRINT
        )
        val signature2 = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-id",
            enrollableType = EnrollableType.FINGERPRINT
        )

        // Then
        assertEquals(signature1.hashCode(), signature2.hashCode())
    }

    @Test
    fun toString_shouldContainAllProperties() {
        // Given
        val signature = EnrollableSignature(
            biometricAuthentication = true,
            algorithmType = HashAlgorithmType.SHA256,
            authenticatorId = "test-auth-id",
            enrollableType = EnrollableType.FACE
        )

        // When
        val result = signature.toString()

        // Then
        assert(result.contains("EnrollableSignature"))
        assert(result.contains("biometricAuthentication=true"))
        assert(result.contains("algorithmType=HmacSHA256"))
        assert(result.contains("authenticatorId=test-auth-id"))
        assert(result.contains("enrollableType=FACE"))
    }
}
