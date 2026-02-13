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
import java.net.URL

@RunWith(AndroidJUnit4::class)
class InitializationInfoTest {

    private val testUri = URL("https://example.com/details")
    private val testCode = "ABC123XYZ"
    private val testClientId = "client-id-123"

    @Test
    fun constructor_withRequiredFields_shouldCreateInstance() {
        // When
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            clientId = testClientId
        )

        // Then
        assertEquals(testUri, info.uri)
        assertEquals(testCode, info.code)
        assertFalse(info.ignoreSSLCertificate)
        assertEquals(testClientId, info.clientId)
    }

    @Test
    fun constructor_withIgnoreSSLCertificateFalse_shouldSetFalse() {
        // When
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = false,
            clientId = testClientId
        )

        // Then
        assertFalse(info.ignoreSSLCertificate)
    }

    @Test
    fun constructor_withIgnoreSSLCertificateTrue_shouldSetTrue() {
        // When
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )

        // Then
        assertTrue(info.ignoreSSLCertificate)
    }

    @Test
    fun constructor_withDifferentUri_shouldSetUri() {
        // Given
        val differentUri = URL("https://different.com/details")

        // When
        val info = InitializationInfo(
            uri = differentUri,
            code = testCode,
            clientId = testClientId
        )

        // Then
        assertEquals(differentUri, info.uri)
    }

    @Test
    fun constructor_withDifferentCode_shouldSetCode() {
        // Given
        val differentCode = "XYZ789ABC"

        // When
        val info = InitializationInfo(
            uri = testUri,
            code = differentCode,
            clientId = testClientId
        )

        // Then
        assertEquals(differentCode, info.code)
    }

    @Test
    fun constructor_withDifferentClientId_shouldSetClientId() {
        // Given
        val differentClientId = "different-client-id"

        // When
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            clientId = differentClientId
        )

        // Then
        assertEquals(differentClientId, info.clientId)
    }

    @Test
    fun serialization_shouldSerializeAndDeserialize() {
        // Given
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(info)
        val deserialized = json.decodeFromString<InitializationInfo>(serialized)

        // Then
        assertEquals(info.uri, deserialized.uri)
        assertEquals(info.code, deserialized.code)
        assertEquals(info.ignoreSSLCertificate, deserialized.ignoreSSLCertificate)
        assertEquals(info.clientId, deserialized.clientId)
    }

    @Test
    fun deserialization_fromJsonString_shouldCreateInstance() {
        // Given
        val jsonString = """
            {
                "details_url": "https://example.com/details",
                "code": "ABC123XYZ",
                "ignoreSSLCertificate": true,
                "client_id": "client-id-123"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val info = json.decodeFromString<InitializationInfo>(jsonString)

        // Then
        assertEquals(testUri, info.uri)
        assertEquals(testCode, info.code)
        assertTrue(info.ignoreSSLCertificate)
        assertEquals(testClientId, info.clientId)
    }

    @Test
    fun deserialization_withDefaultIgnoreSSL_shouldSetFalse() {
        // Given
        val jsonString = """
            {
                "details_url": "https://example.com/details",
                "code": "ABC123XYZ",
                "client_id": "client-id-123"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val info = json.decodeFromString<InitializationInfo>(jsonString)

        // Then
        assertFalse(info.ignoreSSLCertificate)
    }

    @Test
    fun deserialization_withExtraFields_shouldIgnoreExtraFields() {
        // Given
        val jsonString = """
            {
                "details_url": "https://example.com/details",
                "code": "ABC123XYZ",
                "ignoreSSLCertificate": false,
                "client_id": "client-id-123",
                "extraField": "extraValue"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val info = json.decodeFromString<InitializationInfo>(jsonString)

        // Then
        assertEquals(testUri, info.uri)
        assertEquals(testCode, info.code)
        assertFalse(info.ignoreSSLCertificate)
        assertEquals(testClientId, info.clientId)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.uri, copy.uri)
        assertEquals(original.code, copy.code)
        assertEquals(original.ignoreSSLCertificate, copy.ignoreSSLCertificate)
        assertEquals(original.clientId, copy.clientId)
    }

    @Test
    fun copy_withModifiedUri_shouldUpdateOnlyUri() {
        // Given
        val original = InitializationInfo(
            uri = testUri,
            code = testCode,
            clientId = testClientId
        )
        val newUri = URL("https://new.com/details")

        // When
        val modified = original.copy(uri = newUri)

        // Then
        assertEquals(newUri, modified.uri)
        assertEquals(original.code, modified.code)
        assertEquals(original.ignoreSSLCertificate, modified.ignoreSSLCertificate)
        assertEquals(original.clientId, modified.clientId)
    }

    @Test
    fun copy_withModifiedCode_shouldUpdateOnlyCode() {
        // Given
        val original = InitializationInfo(
            uri = testUri,
            code = testCode,
            clientId = testClientId
        )

        // When
        val modified = original.copy(code = "NEWCODE123")

        // Then
        assertEquals(original.uri, modified.uri)
        assertEquals("NEWCODE123", modified.code)
        assertEquals(original.ignoreSSLCertificate, modified.ignoreSSLCertificate)
        assertEquals(original.clientId, modified.clientId)
    }

    @Test
    fun copy_withModifiedIgnoreSSLCertificate_shouldUpdateOnlyIgnoreSSLCertificate() {
        // Given
        val original = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = false,
            clientId = testClientId
        )

        // When
        val modified = original.copy(ignoreSSLCertificate = true)

        // Then
        assertEquals(original.uri, modified.uri)
        assertEquals(original.code, modified.code)
        assertTrue(modified.ignoreSSLCertificate)
        assertEquals(original.clientId, modified.clientId)
    }

    @Test
    fun copy_withModifiedClientId_shouldUpdateOnlyClientId() {
        // Given
        val original = InitializationInfo(
            uri = testUri,
            code = testCode,
            clientId = testClientId
        )

        // When
        val modified = original.copy(clientId = "new-client-id")

        // Then
        assertEquals(original.uri, modified.uri)
        assertEquals(original.code, modified.code)
        assertEquals(original.ignoreSSLCertificate, modified.ignoreSSLCertificate)
        assertEquals("new-client-id", modified.clientId)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val info1 = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )
        val info2 = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )

        // Then
        assertEquals(info1, info2)
    }

    @Test
    fun equals_withDifferentUri_shouldReturnFalse() {
        // Given
        val info1 = InitializationInfo(
            uri = URL("https://example1.com/details"),
            code = testCode,
            clientId = testClientId
        )
        val info2 = InitializationInfo(
            uri = URL("https://example2.com/details"),
            code = testCode,
            clientId = testClientId
        )

        // Then
        assertNotEquals(info1, info2)
    }

    @Test
    fun equals_withDifferentCode_shouldReturnFalse() {
        // Given
        val info1 = InitializationInfo(
            uri = testUri,
            code = "CODE1",
            clientId = testClientId
        )
        val info2 = InitializationInfo(
            uri = testUri,
            code = "CODE2",
            clientId = testClientId
        )

        // Then
        assertNotEquals(info1, info2)
    }

    @Test
    fun equals_withDifferentIgnoreSSLCertificate_shouldReturnFalse() {
        // Given
        val info1 = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )
        val info2 = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = false,
            clientId = testClientId
        )

        // Then
        assertNotEquals(info1, info2)
    }

    @Test
    fun equals_withDifferentClientId_shouldReturnFalse() {
        // Given
        val info1 = InitializationInfo(
            uri = testUri,
            code = testCode,
            clientId = "client1"
        )
        val info2 = InitializationInfo(
            uri = testUri,
            code = testCode,
            clientId = "client2"
        )

        // Then
        assertNotEquals(info1, info2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val info1 = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )
        val info2 = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )

        // Then
        assertEquals(info1.hashCode(), info2.hashCode())
    }

    @Test
    fun toString_shouldContainAllProperties() {
        // Given
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )

        // When
        val result = info.toString()

        // Then
        assert(result.contains("InitializationInfo"))
        assert(result.contains(testCode))
        assert(result.contains(testClientId))
    }

    @Test
    fun allProperties_shouldNotBeNull() {
        // Given
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            clientId = testClientId
        )

        // Then
        assertNotNull(info.uri)
        assertNotNull(info.code)
        assertNotNull(info.clientId)
    }

    @Test
    fun constructor_withEmptyCode_shouldSetEmptyCode() {
        // When
        val info = InitializationInfo(
            uri = testUri,
            code = "",
            clientId = testClientId
        )

        // Then
        assertEquals("", info.code)
    }

    @Test
    fun constructor_withEmptyClientId_shouldSetEmptyClientId() {
        // When
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            clientId = ""
        )

        // Then
        assertEquals("", info.clientId)
    }

    @Test
    fun serialization_withSpecialCharacters_shouldHandleCorrectly() {
        // Given
        val specialCode = "ABC-123_XYZ"
        val specialClientId = "client-id_123"
        val info = InitializationInfo(
            uri = testUri,
            code = specialCode,
            ignoreSSLCertificate = true,
            clientId = specialClientId
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(info)
        val deserialized = json.decodeFromString<InitializationInfo>(serialized)

        // Then
        assertEquals(specialCode, deserialized.code)
        assertEquals(specialClientId, deserialized.clientId)
    }
}


