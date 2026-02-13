/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.cloud

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

@RunWith(AndroidJUnit4::class)
class InitializationInfoTest {

    private val testUri = URL("https://example.com/registration")
    private val testCode = "ABC123XYZ"
    private val testAccountName = "test@example.com"

    @Test
    fun constructor_withAllFields_shouldCreateInstance() {
        // When
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
        )

        // Then
        assertEquals(testUri, info.uri)
        assertEquals(testCode, info.code)
        assertEquals(testAccountName, info.accountName)
    }

    @Test
    fun constructor_withDifferentUri_shouldSetUri() {
        // Given
        val differentUri = URL("https://different.com/register")

        // When
        val info = InitializationInfo(
            uri = differentUri,
            code = testCode,
            accountName = testAccountName
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
            accountName = testAccountName
        )

        // Then
        assertEquals(differentCode, info.code)
    }

    @Test
    fun constructor_withDifferentAccountName_shouldSetAccountName() {
        // Given
        val differentAccountName = "different@example.com"

        // When
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = differentAccountName
        )

        // Then
        assertEquals(differentAccountName, info.accountName)
    }

    @Test
    fun serialization_shouldSerializeAndDeserialize() {
        // Given
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(info)
        val deserialized = json.decodeFromString<InitializationInfo>(serialized)

        // Then
        assertEquals(info.uri, deserialized.uri)
        assertEquals(info.code, deserialized.code)
        assertEquals(info.accountName, deserialized.accountName)
    }

    @Test
    fun deserialization_fromJsonString_shouldCreateInstance() {
        // Given
        val jsonString = """
            {
                "registrationUri": "https://example.com/registration",
                "code": "ABC123XYZ",
                "accountName": "test@example.com"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val info = json.decodeFromString<InitializationInfo>(jsonString)

        // Then
        assertEquals(testUri, info.uri)
        assertEquals(testCode, info.code)
        assertEquals(testAccountName, info.accountName)
    }

    @Test
    fun deserialization_withExtraFields_shouldIgnoreExtraFields() {
        // Given
        val jsonString = """
            {
                "registrationUri": "https://example.com/registration",
                "code": "ABC123XYZ",
                "accountName": "test@example.com",
                "extraField": "extraValue"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val info = json.decodeFromString<InitializationInfo>(jsonString)

        // Then
        assertEquals(testUri, info.uri)
        assertEquals(testCode, info.code)
        assertEquals(testAccountName, info.accountName)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.uri, copy.uri)
        assertEquals(original.code, copy.code)
        assertEquals(original.accountName, copy.accountName)
    }

    @Test
    fun copy_withModifiedUri_shouldUpdateOnlyUri() {
        // Given
        val original = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
        )
        val newUri = URL("https://new.com/registration")

        // When
        val modified = original.copy(uri = newUri)

        // Then
        assertEquals(newUri, modified.uri)
        assertEquals(original.code, modified.code)
        assertEquals(original.accountName, modified.accountName)
    }

    @Test
    fun copy_withModifiedCode_shouldUpdateOnlyCode() {
        // Given
        val original = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
        )

        // When
        val modified = original.copy(code = "NEWCODE123")

        // Then
        assertEquals(original.uri, modified.uri)
        assertEquals("NEWCODE123", modified.code)
        assertEquals(original.accountName, modified.accountName)
    }

    @Test
    fun copy_withModifiedAccountName_shouldUpdateOnlyAccountName() {
        // Given
        val original = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
        )

        // When
        val modified = original.copy(accountName = "new@example.com")

        // Then
        assertEquals(original.uri, modified.uri)
        assertEquals(original.code, modified.code)
        assertEquals("new@example.com", modified.accountName)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val info1 = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
        )
        val info2 = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
        )

        // Then
        assertEquals(info1, info2)
    }

    @Test
    fun equals_withDifferentUri_shouldReturnFalse() {
        // Given
        val info1 = InitializationInfo(
            uri = URL("https://example1.com/registration"),
            code = testCode,
            accountName = testAccountName
        )
        val info2 = InitializationInfo(
            uri = URL("https://example2.com/registration"),
            code = testCode,
            accountName = testAccountName
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
            accountName = testAccountName
        )
        val info2 = InitializationInfo(
            uri = testUri,
            code = "CODE2",
            accountName = testAccountName
        )

        // Then
        assertNotEquals(info1, info2)
    }

    @Test
    fun equals_withDifferentAccountName_shouldReturnFalse() {
        // Given
        val info1 = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = "account1@example.com"
        )
        val info2 = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = "account2@example.com"
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
            accountName = testAccountName
        )
        val info2 = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
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
            accountName = testAccountName
        )

        // When
        val result = info.toString()

        // Then
        assert(result.contains("InitializationInfo"))
        assert(result.contains(testCode))
        assert(result.contains(testAccountName))
    }

    @Test
    fun constructor_withEmptyCode_shouldSetEmptyCode() {
        // When
        val info = InitializationInfo(
            uri = testUri,
            code = "",
            accountName = testAccountName
        )

        // Then
        assertEquals("", info.code)
    }

    @Test
    fun constructor_withEmptyAccountName_shouldSetEmptyAccountName() {
        // When
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = ""
        )

        // Then
        assertEquals("", info.accountName)
    }

    @Test
    fun serialization_withSpecialCharacters_shouldHandleCorrectly() {
        // Given
        val specialAccountName = "test+special@example.com"
        val specialCode = "ABC-123_XYZ"
        val info = InitializationInfo(
            uri = testUri,
            code = specialCode,
            accountName = specialAccountName
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(info)
        val deserialized = json.decodeFromString<InitializationInfo>(serialized)

        // Then
        assertEquals(specialCode, deserialized.code)
        assertEquals(specialAccountName, deserialized.accountName)
    }

    @Test
    fun allProperties_shouldNotBeNull() {
        // Given
        val info = InitializationInfo(
            uri = testUri,
            code = testCode,
            accountName = testAccountName
        )

        // Then
        assertNotNull(info.uri)
        assertNotNull(info.code)
        assertNotNull(info.accountName)
    }
}


