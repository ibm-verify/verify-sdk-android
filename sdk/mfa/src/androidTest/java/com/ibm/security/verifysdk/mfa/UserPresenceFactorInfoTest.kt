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
class UserPresenceFactorInfoTest {

    @Test
    fun constructor_withDefaultValues_shouldCreateInstance() {
        // When
        val factor = UserPresenceFactorInfo()

        // Then
        assertNotNull(factor.id)
        assertEquals("User presence", factor.displayName)
        assertEquals("userpresence", factor.keyName)
        assertEquals(HashAlgorithmType.SHA1, factor.algorithm)
    }

    @Test
    fun constructor_withCustomId_shouldSetId() {
        // Given
        val customId = UUID.randomUUID()

        // When
        val factor = UserPresenceFactorInfo(id = customId)

        // Then
        assertEquals(customId, factor.id)
        assertEquals("User presence", factor.displayName)
        assertEquals("userpresence", factor.keyName)
        assertEquals(HashAlgorithmType.SHA1, factor.algorithm)
    }

    @Test
    fun constructor_withCustomDisplayName_shouldSetDisplayName() {
        // Given
        val customDisplayName = "Custom User Presence"

        // When
        val factor = UserPresenceFactorInfo(displayName = customDisplayName)

        // Then
        assertNotNull(factor.id)
        assertEquals(customDisplayName, factor.displayName)
        assertEquals("userpresence", factor.keyName)
        assertEquals(HashAlgorithmType.SHA1, factor.algorithm)
    }

    @Test
    fun constructor_withCustomKeyName_shouldSetKeyName() {
        // Given
        val customKeyName = "custom_presence_key"

        // When
        val factor = UserPresenceFactorInfo(keyName = customKeyName)

        // Then
        assertNotNull(factor.id)
        assertEquals("User presence", factor.displayName)
        assertEquals(customKeyName, factor.keyName)
        assertEquals(HashAlgorithmType.SHA1, factor.algorithm)
    }

    @Test
    fun constructor_withSHA256Algorithm_shouldSetAlgorithm() {
        // When
        val factor = UserPresenceFactorInfo(algorithm = HashAlgorithmType.SHA256)

        // Then
        assertNotNull(factor.id)
        assertEquals("User presence", factor.displayName)
        assertEquals("userpresence", factor.keyName)
        assertEquals(HashAlgorithmType.SHA256, factor.algorithm)
    }

    @Test
    fun constructor_withSHA384Algorithm_shouldSetAlgorithm() {
        // When
        val factor = UserPresenceFactorInfo(algorithm = HashAlgorithmType.SHA384)

        // Then
        assertEquals(HashAlgorithmType.SHA384, factor.algorithm)
    }

    @Test
    fun constructor_withSHA512Algorithm_shouldSetAlgorithm() {
        // When
        val factor = UserPresenceFactorInfo(algorithm = HashAlgorithmType.SHA512)

        // Then
        assertEquals(HashAlgorithmType.SHA512, factor.algorithm)
    }

    @Test
    fun constructor_withAllCustomValues_shouldSetAllProperties() {
        // Given
        val customId = UUID.randomUUID()
        val customDisplayName = "Device Presence"
        val customKeyName = "device_presence_key"
        val customAlgorithm = HashAlgorithmType.SHA256

        // When
        val factor = UserPresenceFactorInfo(
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
        val factor = UserPresenceFactorInfo()
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(factor)
        val deserialized = json.decodeFromString<UserPresenceFactorInfo>(serialized)

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
        val factor = UserPresenceFactorInfo(
            id = customId,
            displayName = "Custom Presence",
            keyName = "custom_key",
            algorithm = HashAlgorithmType.SHA512
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(factor)
        val deserialized = json.decodeFromString<UserPresenceFactorInfo>(serialized)

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
                "displayName": "Presence Auth",
                "keyName": "presence_key",
                "algorithm": "SHA256"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val factor = json.decodeFromString<UserPresenceFactorInfo>(jsonString)

        // Then
        assertEquals(uuid, factor.id)
        assertEquals("Presence Auth", factor.displayName)
        assertEquals("presence_key", factor.keyName)
        assertEquals(HashAlgorithmType.SHA256, factor.algorithm)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = UserPresenceFactorInfo(
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
        val original = UserPresenceFactorInfo()

        // When
        val modified = original.copy(displayName = "Modified Presence")

        // Then
        assertEquals(original.id, modified.id)
        assertEquals("Modified Presence", modified.displayName)
        assertEquals(original.keyName, modified.keyName)
        assertEquals(original.algorithm, modified.algorithm)
    }

    @Test
    fun copy_withModifiedKeyName_shouldUpdateOnlyKeyName() {
        // Given
        val original = UserPresenceFactorInfo()

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
        val original = UserPresenceFactorInfo()

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
        val factor1 = UserPresenceFactorInfo(
            id = id,
            displayName = "Test",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )
        val factor2 = UserPresenceFactorInfo(
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
        val factor1 = UserPresenceFactorInfo(
            displayName = "Test",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )
        val factor2 = UserPresenceFactorInfo(
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
        val factor1 = UserPresenceFactorInfo(
            id = id,
            displayName = "Test",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )
        val factor2 = UserPresenceFactorInfo(
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
        val factor: Factor = UserPresenceFactorInfo()

        // Then
        assertNotNull(factor.id)
        assertNotNull(factor.displayName)
    }

    @Test
    fun toString_shouldContainAllProperties() {
        // Given
        val factor = UserPresenceFactorInfo(
            displayName = "Test Presence",
            keyName = "test_key",
            algorithm = HashAlgorithmType.SHA256
        )

        // When
        val result = factor.toString()

        // Then
        assert(result.contains("UserPresenceFactorInfo"))
        assert(result.contains("id="))
        assert(result.contains("displayName=Test Presence"))
        assert(result.contains("keyName=test_key"))
        assert(result.contains("algorithm=HmacSHA256"))
    }

    @Test
    fun defaultKeyName_shouldBeUserpresence() {
        // When
        val factor = UserPresenceFactorInfo()

        // Then
        assertEquals("userpresence", factor.keyName)
    }

    @Test
    fun defaultDisplayName_shouldBeUserPresence() {
        // When
        val factor = UserPresenceFactorInfo()

        // Then
        assertEquals("User presence", factor.displayName)
    }

    @Test
    fun defaultAlgorithm_shouldBeSHA1() {
        // When
        val factor = UserPresenceFactorInfo()

        // Then
        assertEquals(HashAlgorithmType.SHA1, factor.algorithm)
    }
}

