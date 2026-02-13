/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class BiometricFactorInfoTest {

    @Test
    fun constructor_withDefaultValues_shouldCreateInstance() {
        // When
        val factor = BiometricFactorInfo()

        // Then
        assertNotNull(factor.id)
        assertEquals("Biometric", factor.displayName)
        assertEquals("biometric", factor.keyName)
        assertEquals(HashAlgorithmType.SHA1, factor.algorithm)
    }

    @Test
    fun constructor_withCustomId_shouldSetId() {
        // Given
        val customId = UUID.randomUUID()

        // When
        val factor = BiometricFactorInfo(id = customId)

        // Then
        assertEquals(customId, factor.id)
        assertEquals("Biometric", factor.displayName)
        assertEquals("biometric", factor.keyName)
        assertEquals(HashAlgorithmType.SHA1, factor.algorithm)
    }

    @Test
    fun constructor_withCustomDisplayName_shouldSetDisplayName() {
        // Given
        val customDisplayName = "Custom Biometric"

        // When
        val factor = BiometricFactorInfo(displayName = customDisplayName)

        // Then
        assertNotNull(factor.id)
        assertEquals(customDisplayName, factor.displayName)
        assertEquals("biometric", factor.keyName)
        assertEquals(HashAlgorithmType.SHA1, factor.algorithm)
    }

    @Test
    fun constructor_withCustomKeyName_shouldSetKeyName() {
        // Given
        val customKeyName = "custom_biometric_key"

        // When
        val factor = BiometricFactorInfo(keyName = customKeyName)

        // Then
        assertNotNull(factor.id)
        assertEquals("Biometric", factor.displayName)
        assertEquals(customKeyName, factor.keyName)
        assertEquals(HashAlgorithmType.SHA1, factor.algorithm)
    }

    @Test
    fun constructor_withSHA256Algorithm_shouldSetAlgorithm() {
        // When
        val factor = BiometricFactorInfo(algorithm = HashAlgorithmType.SHA256)

        // Then
        assertNotNull(factor.id)
        assertEquals("Biometric", factor.displayName)
        assertEquals("biometric", factor.keyName)
        assertEquals(HashAlgorithmType.SHA256, factor.algorithm)
    }

    @Test
    fun constructor_withSHA384Algorithm_shouldSetAlgorithm() {
        // When
        val factor = BiometricFactorInfo(algorithm = HashAlgorithmType.SHA384)

        // Then
        assertEquals(HashAlgorithmType.SHA384, factor.algorithm)
    }

    @Test
    fun constructor_withSHA512Algorithm_shouldSetAlgorithm() {
        // When
        val factor = BiometricFactorInfo(algorithm = HashAlgorithmType.SHA512)

        // Then
        assertEquals(HashAlgorithmType.SHA512, factor.algorithm)
    }

    @Test
    fun constructor_withAllCustomValues_shouldSetAllProperties() {
        // Given
        val customId = UUID.randomUUID()
        val customDisplayName = "Fingerprint Scanner"
        val customKeyName = "fingerprint_key"
        val customAlgorithm = HashAlgorithmType.SHA256

        // When
        val factor = BiometricFactorInfo(
            id = customId,
            displayName = customDisplayName,
            keyName = customKeyName,
            algorithm = customAlgorithm
        )

        // Then
        assertEquals(customId, factor.id)
        assertEquals(customDisplayName, factor.displayName)
        assertEquals(customKeyName, factor.keyName)
        assertEquals(customAlgorithm, factor.algorithm)
    }

    @Test
    fun serialization_withDefaultValues_shouldSerializeAndDeserialize() {
        // Given
        val factor = BiometricFactorInfo()
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(factor)
        val deserialized = json.decodeFromString<BiometricFactorInfo>(serialized)

        // Then
        assertEquals(factor.id, deserialized.id)
        assertEquals(factor.displayName, deserialized.displayName)
        assertEquals(factor.keyName, deserialized.keyName)
        assertEquals(factor.algorithm, deserialized.algorithm)
    }

    @Test
    fun serialization_withCustomValues_shouldSerializeAndDeserialize() {
        // Given
        val customId = UUID.randomUUID()
        val factor = BiometricFactorInfo(
            id = customId,
            displayName = "Face Recognition",
            keyName = "face_key",
            algorithm = HashAlgorithmType.SHA512
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(factor)
        val deserialized = json.decodeFromString<BiometricFactorInfo>(serialized)

        // Then
        assertEquals(factor.id, deserialized.id)
        assertEquals(factor.displayName, deserialized.displayName)
        assertEquals(factor.keyName, deserialized.keyName)
        assertEquals(factor.algorithm, deserialized.algorithm)
    }

    @Test
    fun deserialization_fromJsonString_shouldCreateInstance() {
        // Given
        val uuid = UUID.randomUUID()
        val jsonString = """
            {
                "id": "$uuid",
                "displayName": "Biometric Auth",
                "keyName": "bio_key",
                "algorithm": "SHA256"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val factor = json.decodeFromString<BiometricFactorInfo>(jsonString)

        // Then
        assertEquals(uuid, factor.id)
        assertEquals("Biometric Auth", factor.displayName)
        assertEquals("bio_key", factor.keyName)
        assertEquals(HashAlgorithmType.SHA256, factor.algorithm)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = BiometricFactorInfo(
            displayName = "Original",
            keyName = "original_key",
            algorithm = HashAlgorithmType.SHA256
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.id, copy.id)
        assertEquals(original.displayName, copy.displayName)
        assertEquals(original.keyName, copy.keyName)
        assertEquals(original.algorithm, copy.algorithm)
    }

    @Test
    fun copy_withModifiedDisplayName_shouldUpdateOnlyDisplayName() {
        // Given
        val original = BiometricFactorInfo()

        // When
        val modified = original.copy(displayName = "Modified Biometric")

        // Then
        assertEquals(original.id, modified.id)
        assertEquals("Modified Biometric", modified.displayName)
        assertEquals(original.keyName, modified.keyName)
        assertEquals(original.algorithm, modified.algorithm)
    }

    @Test
    fun copy_withModifiedKeyName_shouldUpdateOnlyKeyName() {
        // Given
        val original = BiometricFactorInfo()

        // When
        val modified = original.copy(keyName = "new_key")

        // Then
        assertEquals(original.id, modified.id)
        assertEquals(original.displayName, modified.displayName)
        assertEquals("new_key", modified.keyName)
        assertEquals(original.algorithm, modified.algorithm)
    }

    @Test
    fun copy_withModifiedAlgorithm_shouldUpdateOnlyAlgorithm() {
        // Given
        val original = BiometricFactorInfo()

        // When
        val modified = original.copy(algorithm = HashAlgorithmType.SHA512)

        // Then
        assertEquals(original.id, modified.id)
        assertEquals(original.displayName, modified.displayName)
        assertEquals(original.keyName, modified.keyName)
        assertEquals(HashAlgorithmType.SHA512, modified.algorithm)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val id = UUID.randomUUID()
        val factor1 = BiometricFactorInfo(
            id = id,
            displayName = "Test",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )
        val factor2 = BiometricFactorInfo(
            id = id,
            displayName = "Test",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )

        // Then
        assertEquals(factor1, factor2)
    }

    @Test
    fun equals_withDifferentId_shouldReturnFalse() {
        // Given
        val factor1 = BiometricFactorInfo(
            displayName = "Test",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )
        val factor2 = BiometricFactorInfo(
            displayName = "Test",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )

        // Then
        assertNotEquals(factor1, factor2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val id = UUID.randomUUID()
        val factor1 = BiometricFactorInfo(
            id = id,
            displayName = "Test",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )
        val factor2 = BiometricFactorInfo(
            id = id,
            displayName = "Test",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )

        // Then
        assertEquals(factor1.hashCode(), factor2.hashCode())
    }

    @Test
    fun implementsFactor_shouldHaveIdAndDisplayName() {
        // Given
        val factor: Factor = BiometricFactorInfo()

        // Then
        assertNotNull(factor.id)
        assertNotNull(factor.displayName)
    }

    @Test
    fun toString_shouldContainAllProperties() {
        // Given
        val factor = BiometricFactorInfo(
            displayName = "Test Biometric",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )

        // When
        val result = factor.toString()

        // Then
        assert(result.contains("BiometricFactorInfo"))
        assert(result.contains("id="))
        assert(result.contains("displayName=Test Biometric"))
        assert(result.contains("keyName=test_key"))
        assert(result.contains("algorithm=HmacSHA256"))
    }
}

