package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith

private val json = Json {
    encodeDefaults = true
    explicitNulls = false
    ignoreUnknownKeys = true
    isLenient = true
}

@RunWith(AndroidJUnit4::class)
class PublicKeyCredentialTypeTest {

    @Test
    fun testSerialization() {
        val credentialType = PublicKeyCredentialType.PUBLIC_KEY
        val jsonString = json.encodeToString(PublicKeyCredentialType.serializer(), credentialType)
        val expectedJson = """"public-key""""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testDeserialization() {
        val jsonString = """"public-key""""
        val credentialType = json.decodeFromString(PublicKeyCredentialType.serializer(), jsonString)
        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, credentialType)
    }

    @Test
    fun testEnumValue() {
        val credentialType = PublicKeyCredentialType.PUBLIC_KEY
        assertEquals("public-key", credentialType.value)
    }

    @Test
    fun testEquality() {
        val credentialType1 = PublicKeyCredentialType.PUBLIC_KEY
        val credentialType2 = PublicKeyCredentialType.PUBLIC_KEY

        assertEquals(credentialType1, credentialType2)
    }

    @Test
    fun testInequality() {
        val credentialType = PublicKeyCredentialType.PUBLIC_KEY
        assertNotEquals("public-key", credentialType)  // Ensure comparison against string is false
    }
}
