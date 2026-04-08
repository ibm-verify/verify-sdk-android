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
class AuthenticatorTransportTest {

    @Test
    fun testEnumValue() {
        val transport = AuthenticatorTransport.USB
        assertEquals("usb", transport.value)
    }

    @Test
    fun testEnumSerialization() {
        val transport = AuthenticatorTransport.NFC
        val jsonString = json.encodeToString(AuthenticatorTransport.serializer(), transport)
        val expectedJson = """"nfc""""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testEnumDeserialization() {
        val jsonString = """"ble""""
        val transport = json.decodeFromString(AuthenticatorTransport.serializer(), jsonString)
        assertEquals(AuthenticatorTransport.BLE, transport)
    }

    @Test(expected = SerializationException::class)
    fun testEnumDeserialization_invalidValue() {
        val jsonString = """"invalid-transport""""
        json.decodeFromString(AuthenticatorTransport.serializer(), jsonString)
    }

    @Test
    fun testEnumValues() {
        val expectedValues = listOf(
            AuthenticatorTransport.USB,
            AuthenticatorTransport.NFC,
            AuthenticatorTransport.BLE,
            AuthenticatorTransport.INTERNAL,
            AuthenticatorTransport.HYBRID
        )
        val actualValues = AuthenticatorTransport.values().toList()
        assertEquals(expectedValues, actualValues)
    }

    @Test
    fun testEnumValueOf() {
        val transport = AuthenticatorTransport.valueOf("INTERNAL")
        assertEquals(AuthenticatorTransport.INTERNAL, transport)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testEnumValueOf_invalidName() {
        AuthenticatorTransport.valueOf("INVALID_NAME")
    }
}
