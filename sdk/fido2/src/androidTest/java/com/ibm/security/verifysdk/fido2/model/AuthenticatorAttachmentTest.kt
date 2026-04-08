package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import kotlinx.serialization.SerializationException
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

private val json = Json {
    encodeDefaults = true
    explicitNulls = false
    ignoreUnknownKeys = true
    isLenient = true
}

@RunWith(AndroidJUnit4::class)
class AuthenticatorAttachmentTest {

    @Test
    fun testEnumValue() {
        val attachment = AuthenticatorAttachment.PLATFORM
        assertEquals("platform", attachment.value)
    }

    @Test
    fun testEnumSerialization() {
        val attachment = AuthenticatorAttachment.CROSS_PLATFORM
        val jsonString = json.encodeToString(AuthenticatorAttachment.serializer(), attachment)
        val expectedJson = """"cross-platform""""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testEnumDeserialization() {
        val jsonString = """"platform""""
        val attachment = json.decodeFromString(AuthenticatorAttachment.serializer(), jsonString)
        assertEquals(AuthenticatorAttachment.PLATFORM, attachment)
    }

    @Test(expected = SerializationException::class)
    fun testEnumDeserialization_invalidValue() {
        val jsonString = """"invalid-attachment""""
        json.decodeFromString(AuthenticatorAttachment.serializer(), jsonString)
    }

    @Test
    fun testEnumValues() {
        val expectedValues = listOf(
            AuthenticatorAttachment.PLATFORM,
            AuthenticatorAttachment.CROSS_PLATFORM
        )
        val actualValues = AuthenticatorAttachment.values().toList()
        assertEquals(expectedValues, actualValues)
    }

    @Test
    fun testEnumValueOf() {
        val attachment = AuthenticatorAttachment.valueOf("CROSS_PLATFORM")
        assertEquals(AuthenticatorAttachment.CROSS_PLATFORM, attachment)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testEnumValueOf_invalidName() {
        AuthenticatorAttachment.valueOf("INVALID_NAME")
    }
}
