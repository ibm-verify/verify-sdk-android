package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import kotlinx.serialization.SerializationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

private val json = Json {
    encodeDefaults = true
    explicitNulls = false
    ignoreUnknownKeys = true
    isLenient = true
}

@RunWith(AndroidJUnit4::class)
class PublicKeyCredentialDescriptorTest {

    @Test
    fun testDefaultValues() {
        val descriptor = PublicKeyCredentialDescriptor(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            id = "test_id"
        )

        assertNull(descriptor.transports)
    }

    @Test
    fun testCustomValues() {
        val transports = arrayListOf(
            AuthenticatorTransport.USB,
            AuthenticatorTransport.NFC
        )
        val descriptor = PublicKeyCredentialDescriptor(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            id = "test_id",
            transports = transports
        )

        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, descriptor.type)
        assertEquals("test_id", descriptor.id)
        assertEquals(2, descriptor.transports?.size)
        assertTrue(descriptor.transports!!.contains(AuthenticatorTransport.USB))
        assertTrue(descriptor.transports!!.contains(AuthenticatorTransport.NFC))
    }

    @Test
    fun testSerialization() {
        val transports = arrayListOf(AuthenticatorTransport.BLE)
        val descriptor = PublicKeyCredentialDescriptor(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            id = "test_id",
            transports = transports
        )

        val jsonString = json.encodeToString(PublicKeyCredentialDescriptor.serializer(), descriptor)
        val expectedJson = """{"type":"public-key","id":"test_id","transports":["ble"]}"""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testDeserialization() {
        val jsonString = """{"type":"public-key","id":"test_id","transports":["nfc"]}"""
        val descriptor = json.decodeFromString(PublicKeyCredentialDescriptor.serializer(), jsonString)

        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, descriptor.type)
        assertEquals("test_id", descriptor.id)
        assertNotNull(descriptor.transports)
        assertEquals(1, descriptor.transports?.size)
        assertTrue(descriptor.transports!!.contains(AuthenticatorTransport.NFC))
    }

    @Test
    fun testDeserializationWithoutTransports() {
        val jsonString = """{"type":"public-key","id":"test_id"}"""
        val descriptor = json.decodeFromString<PublicKeyCredentialDescriptor>(jsonString)

        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, descriptor.type)
        assertEquals("test_id", descriptor.id)
        assertNull(descriptor.transports)
    }

    @Test(expected = SerializationException::class)
    fun testDeserialization_invalidTransport() {
        val jsonString = """{"type":"public-key","id":"test_id","transports":["invalid"]}"""
        json.decodeFromString<PublicKeyCredentialDescriptor>(jsonString)
    }
}
