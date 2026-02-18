/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.onprem

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EnrollmentResultTest {

    private val testLocation = "https://example.com/resource/123"
    private val testResourceType = "User"
    private val testId = "user-id-123"
    private val testUserName = "testuser@example.com"

    @Test
    fun enrollmentResult_constructor_shouldCreateInstance() {
        // Given
        val meta = Meta(location = testLocation, resourceType = testResourceType)
        val authenticator = Authenticator()
        val resource = Resources(
            meta = meta,
            id = testId,
            userName = testUserName,
            authenticator = authenticator
        )

        // When
        val result = EnrollmentResult(
            totalResults = 1,
            schemas = listOf("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
            resources = listOf(resource)
        )

        // Then
        assertEquals(1, result.totalResults)
        assertEquals(1, result.schemas.size)
        assertEquals(1, result.resources.size)
    }

    @Test
    fun enrollmentResult_serialization_shouldSerializeAndDeserialize() {
        // Given
        val meta = Meta(location = testLocation, resourceType = testResourceType)
        val authenticator = Authenticator()
        val resource = Resources(
            meta = meta,
            id = testId,
            userName = testUserName,
            authenticator = authenticator
        )
        val result = EnrollmentResult(
            totalResults = 1,
            schemas = listOf("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
            resources = listOf(resource)
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(result)
        val deserialized = json.decodeFromString<EnrollmentResult>(serialized)

        // Then
        assertEquals(result.totalResults, deserialized.totalResults)
        assertEquals(result.schemas.size, deserialized.schemas.size)
        assertEquals(result.resources.size, deserialized.resources.size)
    }

    @Test
    fun enrollmentResult_copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val meta = Meta(location = testLocation, resourceType = testResourceType)
        val authenticator = Authenticator()
        val resource = Resources(
            meta = meta,
            id = testId,
            userName = testUserName,
            authenticator = authenticator
        )
        val original = EnrollmentResult(
            totalResults = 1,
            schemas = listOf("schema1"),
            resources = listOf(resource)
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.totalResults, copy.totalResults)
        assertEquals(original.schemas, copy.schemas)
        assertEquals(original.resources.size, copy.resources.size)
    }

    // Resources tests
    @Test
    fun resources_constructor_shouldCreateInstance() {
        // Given
        val meta = Meta(location = testLocation, resourceType = testResourceType)
        val authenticator = Authenticator()

        // When
        val resource = Resources(
            meta = meta,
            id = testId,
            userName = testUserName,
            authenticator = authenticator
        )

        // Then
        assertEquals(meta, resource.meta)
        assertEquals(testId, resource.id)
        assertEquals(testUserName, resource.userName)
        assertEquals(authenticator, resource.authenticator)
    }

    @Test
    fun resources_serialization_shouldSerializeAndDeserialize() {
        // Given
        val meta = Meta(location = testLocation, resourceType = testResourceType)
        val authenticator = Authenticator()
        val resource = Resources(
            meta = meta,
            id = testId,
            userName = testUserName,
            authenticator = authenticator
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(resource)
        val deserialized = json.decodeFromString<Resources>(serialized)

        // Then
        assertEquals(resource.id, deserialized.id)
        assertEquals(resource.userName, deserialized.userName)
        assertEquals(resource.meta.location, deserialized.meta.location)
    }

    @Test
    fun resources_copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val meta = Meta(location = testLocation, resourceType = testResourceType)
        val authenticator = Authenticator()
        val original = Resources(
            meta = meta,
            id = testId,
            userName = testUserName,
            authenticator = authenticator
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.meta, copy.meta)
        assertEquals(original.id, copy.id)
        assertEquals(original.userName, copy.userName)
    }

    // Meta tests
    @Test
    fun meta_constructor_shouldCreateInstance() {
        // When
        val meta = Meta(
            location = testLocation,
            resourceType = testResourceType
        )

        // Then
        assertEquals(testLocation, meta.location)
        assertEquals(testResourceType, meta.resourceType)
    }

    @Test
    fun meta_serialization_shouldSerializeAndDeserialize() {
        // Given
        val meta = Meta(
            location = testLocation,
            resourceType = testResourceType
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(meta)
        val deserialized = json.decodeFromString<Meta>(serialized)

        // Then
        assertEquals(meta.location, deserialized.location)
        assertEquals(meta.resourceType, deserialized.resourceType)
    }

    @Test
    fun meta_copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = Meta(
            location = testLocation,
            resourceType = testResourceType
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.location, copy.location)
        assertEquals(original.resourceType, copy.resourceType)
    }

    @Test
    fun meta_equals_withSameValues_shouldReturnTrue() {
        // Given
        val meta1 = Meta(location = testLocation, resourceType = testResourceType)
        val meta2 = Meta(location = testLocation, resourceType = testResourceType)

        // Then
        assertEquals(meta1, meta2)
    }

    @Test
    fun meta_equals_withDifferentLocation_shouldReturnFalse() {
        // Given
        val meta1 = Meta(location = "location1", resourceType = testResourceType)
        val meta2 = Meta(location = "location2", resourceType = testResourceType)

        // Then
        assertNotEquals(meta1, meta2)
    }

    // Authenticator tests
    @Test
    fun authenticator_constructor_withDefaultValues_shouldCreateInstance() {
        // When
        val authenticator = Authenticator()

        // Then
        assertNotNull(authenticator)
    }

    @Test
    fun authenticator_constructor_withUserPresenceMethods_shouldSetMethods() {
        // Given
        val userPresenceMethod = UserPresenceMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val authenticator = Authenticator(
            userPresenceMethods = listOf(userPresenceMethod)
        )

        // Then
        assertNotNull(authenticator.userPresenceMethods)
        assertEquals(1, authenticator.userPresenceMethods?.size)
        assertEquals(userPresenceMethod, authenticator.userPresenceMethods?.get(0))
    }

    @Test
    fun authenticator_constructor_withFingerprintMethods_shouldSetMethods() {
        // Given
        val fingerprintMethod = FingerprintMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val authenticator = Authenticator(
            fingerprintMethods = listOf(fingerprintMethod)
        )

        // Then
        assertNotNull(authenticator.fingerprintMethods)
        assertEquals(1, authenticator.fingerprintMethods?.size)
        assertEquals(fingerprintMethod, authenticator.fingerprintMethods?.get(0))
    }

    @Test
    fun authenticator_serialization_shouldSerializeAndDeserialize() {
        // Given
        val userPresenceMethod = UserPresenceMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = true,
            algorithm = "SHA256"
        )
        val authenticator = Authenticator(userPresenceMethods = listOf(userPresenceMethod))
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(authenticator)
        val deserialized = json.decodeFromString<Authenticator>(serialized)

        // Then
        assertEquals(authenticator.userPresenceMethods?.size, deserialized.userPresenceMethods?.size)
    }

    // UserPresenceMethod tests
    @Test
    fun userPresenceMethod_constructor_shouldCreateInstance() {
        // When
        val method = UserPresenceMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = true,
            algorithm = "SHA256"
        )

        // Then
        assertEquals("method-id-1", method.id)
        assertEquals("keyHandle1", method.keyHandle)
        assertEquals("authenticator1", method.authenticator)
        assertTrue(method.enabled)
        assertEquals("SHA256", method.algorithm)
    }

    @Test
    fun userPresenceMethod_withEnabledFalse_shouldSetFalse() {
        // When
        val method = UserPresenceMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = false,
            algorithm = "SHA256"
        )

        // Then
        assertFalse(method.enabled)
    }

    @Test
    fun userPresenceMethod_serialization_shouldSerializeAndDeserialize() {
        // Given
        val method = UserPresenceMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = true,
            algorithm = "SHA256"
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(method)
        val deserialized = json.decodeFromString<UserPresenceMethod>(serialized)

        // Then
        assertEquals(method.id, deserialized.id)
        assertEquals(method.keyHandle, deserialized.keyHandle)
        assertEquals(method.authenticator, deserialized.authenticator)
        assertEquals(method.enabled, deserialized.enabled)
        assertEquals(method.algorithm, deserialized.algorithm)
    }

    @Test
    fun userPresenceMethod_copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = UserPresenceMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.id, copy.id)
        assertEquals(original.keyHandle, copy.keyHandle)
        assertEquals(original.authenticator, copy.authenticator)
        assertEquals(original.enabled, copy.enabled)
        assertEquals(original.algorithm, copy.algorithm)
    }

    @Test
    fun userPresenceMethod_equals_withSameValues_shouldReturnTrue() {
        // Given
        val method1 = UserPresenceMethod("id", "key", "auth", true, "SHA256")
        val method2 = UserPresenceMethod("id", "key", "auth", true, "SHA256")

        // Then
        assertEquals(method1, method2)
    }

    // FingerprintMethod tests
    @Test
    fun fingerprintMethod_constructor_shouldCreateInstance() {
        // When
        val method = FingerprintMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = true,
            algorithm = "SHA256"
        )

        // Then
        assertEquals("method-id-1", method.id)
        assertEquals("keyHandle1", method.keyHandle)
        assertEquals("authenticator1", method.authenticator)
        assertTrue(method.enabled)
        assertEquals("SHA256", method.algorithm)
    }

    @Test
    fun fingerprintMethod_withEnabledFalse_shouldSetFalse() {
        // When
        val method = FingerprintMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = false,
            algorithm = "SHA256"
        )

        // Then
        assertFalse(method.enabled)
    }

    @Test
    fun fingerprintMethod_serialization_shouldSerializeAndDeserialize() {
        // Given
        val method = FingerprintMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = true,
            algorithm = "SHA256"
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(method)
        val deserialized = json.decodeFromString<FingerprintMethod>(serialized)

        // Then
        assertEquals(method.id, deserialized.id)
        assertEquals(method.keyHandle, deserialized.keyHandle)
        assertEquals(method.authenticator, deserialized.authenticator)
        assertEquals(method.enabled, deserialized.enabled)
        assertEquals(method.algorithm, deserialized.algorithm)
    }

    @Test
    fun fingerprintMethod_copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = FingerprintMethod(
            id = "method-id-1",
            keyHandle = "keyHandle1",
            authenticator = "authenticator1",
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.id, copy.id)
        assertEquals(original.keyHandle, copy.keyHandle)
        assertEquals(original.authenticator, copy.authenticator)
        assertEquals(original.enabled, copy.enabled)
        assertEquals(original.algorithm, copy.algorithm)
    }

    @Test
    fun fingerprintMethod_equals_withSameValues_shouldReturnTrue() {
        // Given
        val method1 = FingerprintMethod("id", "key", "auth", true, "SHA256")
        val method2 = FingerprintMethod("id", "key", "auth", true, "SHA256")

        // Then
        assertEquals(method1, method2)
    }

    @Test
    fun fingerprintMethod_equals_withDifferentId_shouldReturnFalse() {
        // Given
        val method1 = FingerprintMethod("id1", "key", "auth", true, "SHA256")
        val method2 = FingerprintMethod("id2", "key", "auth", true, "SHA256")

        // Then
        assertNotEquals(method1, method2)
    }

    @Test
    fun allDataClasses_toString_shouldContainClassName() {
        // Given
        val meta = Meta(testLocation, testResourceType)
        val userPresenceMethod = UserPresenceMethod("id", "key", "auth", true, "SHA256")
        val fingerprintMethod = FingerprintMethod("id", "key", "auth", true, "SHA256")
        val authenticator = Authenticator()
        val resource = Resources(meta, testId, testUserName, authenticator)
        val enrollmentResult = EnrollmentResult(1, listOf("schema"), listOf(resource))

        // Then
        assert(meta.toString().contains("Meta"))
        assert(userPresenceMethod.toString().contains("UserPresenceMethod"))
        assert(fingerprintMethod.toString().contains("FingerprintMethod"))
        assert(authenticator.toString().contains("Authenticator"))
        assert(resource.toString().contains("Resources"))
        assert(enrollmentResult.toString().contains("EnrollmentResult"))
    }
}


