/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.onprem

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VerificationInfoTest {

    private val testMechanism = "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:fingerprint"
    private val testLocation = "https://example.com/verification/123"
    private val testType = "verification"
    private val testServerChallenge = "challenge123"
    private val testKeyHandles = listOf("keyHandle1", "keyHandle2", "keyHandle3")

    @Test
    fun constructor_withAllFields_shouldCreateInstance() {
        // When
        val info = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // Then
        assertEquals(testMechanism, info.mechanism)
        assertEquals(testLocation, info.location)
        assertEquals(testType, info.type)
        assertEquals(testServerChallenge, info.serverChallenge)
        assertEquals(testKeyHandles, info.keyHandles)
    }

    @Test
    fun constructor_withEmptyKeyHandles_shouldSetEmptyList() {
        // When
        val info = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = emptyList()
        )

        // Then
        assertTrue(info.keyHandles.isEmpty())
    }

    @Test
    fun constructor_withSingleKeyHandle_shouldSetSingleItem() {
        // Given
        val singleKeyHandle = listOf("keyHandle1")

        // When
        val info = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = singleKeyHandle
        )

        // Then
        assertEquals(1, info.keyHandles.size)
        assertEquals("keyHandle1", info.keyHandles[0])
    }

    @Test
    fun constructor_withDifferentMechanism_shouldSetMechanism() {
        // Given
        val differentMechanism = "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence"

        // When
        val info = VerificationInfo(
            mechanism = differentMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // Then
        assertEquals(differentMechanism, info.mechanism)
    }

    @Test
    fun serialization_shouldSerializeAndDeserialize() {
        // Given
        val info = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(info)
        val deserialized = json.decodeFromString<VerificationInfo>(serialized)

        // Then
        assertEquals(info.mechanism, deserialized.mechanism)
        assertEquals(info.location, deserialized.location)
        assertEquals(info.type, deserialized.type)
        assertEquals(info.serverChallenge, deserialized.serverChallenge)
        assertEquals(info.keyHandles, deserialized.keyHandles)
    }

    @Test
    fun deserialization_fromJsonString_shouldCreateInstance() {
        // Given
        val jsonString = """
            {
                "mechanism": "$testMechanism",
                "location": "$testLocation",
                "type": "$testType",
                "serverChallenge": "$testServerChallenge",
                "keyHandles": ["keyHandle1", "keyHandle2", "keyHandle3"]
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val info = json.decodeFromString<VerificationInfo>(jsonString)

        // Then
        assertEquals(testMechanism, info.mechanism)
        assertEquals(testLocation, info.location)
        assertEquals(testType, info.type)
        assertEquals(testServerChallenge, info.serverChallenge)
        assertEquals(3, info.keyHandles.size)
    }

    @Test
    fun deserialization_withExtraFields_shouldIgnoreExtraFields() {
        // Given
        val jsonString = """
            {
                "mechanism": "$testMechanism",
                "location": "$testLocation",
                "type": "$testType",
                "serverChallenge": "$testServerChallenge",
                "keyHandles": ["keyHandle1"],
                "extraField": "extraValue"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val info = json.decodeFromString<VerificationInfo>(jsonString)

        // Then
        assertEquals(testMechanism, info.mechanism)
        assertEquals(testLocation, info.location)
        assertEquals(testType, info.type)
        assertEquals(testServerChallenge, info.serverChallenge)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.mechanism, copy.mechanism)
        assertEquals(original.location, copy.location)
        assertEquals(original.type, copy.type)
        assertEquals(original.serverChallenge, copy.serverChallenge)
        assertEquals(original.keyHandles, copy.keyHandles)
    }

    @Test
    fun copy_withModifiedMechanism_shouldUpdateOnlyMechanism() {
        // Given
        val original = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )
        val newMechanism = "urn:ibm:security:authentication:asf:mechanism:totp"

        // When
        val modified = original.copy(mechanism = newMechanism)

        // Then
        assertEquals(newMechanism, modified.mechanism)
        assertEquals(original.location, modified.location)
        assertEquals(original.type, modified.type)
        assertEquals(original.serverChallenge, modified.serverChallenge)
    }

    @Test
    fun copy_withModifiedLocation_shouldUpdateOnlyLocation() {
        // Given
        val original = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // When
        val modified = original.copy(location = "https://new.com/verification/456")

        // Then
        assertEquals(original.mechanism, modified.mechanism)
        assertEquals("https://new.com/verification/456", modified.location)
        assertEquals(original.type, modified.type)
    }

    @Test
    fun copy_withModifiedServerChallenge_shouldUpdateOnlyServerChallenge() {
        // Given
        val original = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // When
        val modified = original.copy(serverChallenge = "newChallenge456")

        // Then
        assertEquals("newChallenge456", modified.serverChallenge)
        assertEquals(original.mechanism, modified.mechanism)
        assertEquals(original.location, modified.location)
    }

    @Test
    fun copy_withModifiedKeyHandles_shouldUpdateOnlyKeyHandles() {
        // Given
        val original = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )
        val newKeyHandles = listOf("newKey1", "newKey2")

        // When
        val modified = original.copy(keyHandles = newKeyHandles)

        // Then
        assertEquals(newKeyHandles, modified.keyHandles)
        assertEquals(original.mechanism, modified.mechanism)
        assertEquals(original.serverChallenge, modified.serverChallenge)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val info1 = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )
        val info2 = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // Then
        assertEquals(info1, info2)
    }

    @Test
    fun equals_withDifferentMechanism_shouldReturnFalse() {
        // Given
        val info1 = VerificationInfo(
            mechanism = "mechanism1",
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )
        val info2 = VerificationInfo(
            mechanism = "mechanism2",
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // Then
        assertNotEquals(info1, info2)
    }

    @Test
    fun equals_withDifferentServerChallenge_shouldReturnFalse() {
        // Given
        val info1 = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = "challenge1",
            keyHandles = testKeyHandles
        )
        val info2 = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = "challenge2",
            keyHandles = testKeyHandles
        )

        // Then
        assertNotEquals(info1, info2)
    }

    @Test
    fun equals_withDifferentKeyHandles_shouldReturnFalse() {
        // Given
        val info1 = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = listOf("key1")
        )
        val info2 = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = listOf("key2")
        )

        // Then
        assertNotEquals(info1, info2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val info1 = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )
        val info2 = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // Then
        assertEquals(info1.hashCode(), info2.hashCode())
    }

    @Test
    fun toString_shouldContainAllProperties() {
        // Given
        val info = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // When
        val result = info.toString()

        // Then
        assert(result.contains("VerificationInfo"))
        assert(result.contains(testType))
        assert(result.contains(testServerChallenge))
    }

    @Test
    fun allProperties_shouldNotBeNull() {
        // Given
        val info = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // Then
        assertNotNull(info.mechanism)
        assertNotNull(info.location)
        assertNotNull(info.type)
        assertNotNull(info.serverChallenge)
        assertNotNull(info.keyHandles)
    }

    @Test
    fun serverChallenge_isMutable_shouldAllowModification() {
        // Given
        val info = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = testKeyHandles
        )

        // When
        info.serverChallenge = "modifiedChallenge"

        // Then
        assertEquals("modifiedChallenge", info.serverChallenge)
    }

    @Test
    fun keyHandles_withMultipleItems_shouldMaintainOrder() {
        // Given
        val orderedKeyHandles = listOf("first", "second", "third", "fourth")

        // When
        val info = VerificationInfo(
            mechanism = testMechanism,
            location = testLocation,
            type = testType,
            serverChallenge = testServerChallenge,
            keyHandles = orderedKeyHandles
        )

        // Then
        assertEquals("first", info.keyHandles[0])
        assertEquals("second", info.keyHandles[1])
        assertEquals("third", info.keyHandles[2])
        assertEquals("fourth", info.keyHandles[3])
    }
}
