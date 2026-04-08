package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import kotlinx.serialization.SerializationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert

private val json = Json {
    encodeDefaults = true
    explicitNulls = false
    ignoreUnknownKeys = true
    isLenient = true
}

@RunWith(AndroidJUnit4::class)
class PublicKeyCredentialRequestOptionsTest {

    @Test
    fun testSerializationWithAllFields() {
        val allowCredentials = arrayListOf(
            PublicKeyCredentialDescriptor(
                type = PublicKeyCredentialType.PUBLIC_KEY,
                id = "credentialId",
                transports = arrayListOf(AuthenticatorTransport.USB)
            )
        )
        val options = PublicKeyCredentialRequestOptions(
            rpId = "example.com",
            timeout = 60000,
            challenge = "randomChallenge",
            allowCredentials = allowCredentials,
            userVerification = "preferred",
            status = "success",
            errorMessage = ""
        )

        val jsonString = json.encodeToString(PublicKeyCredentialRequestOptions.serializer(), options)
        val expectedJson = """{"rpId":"example.com","timeout":60000,"challenge":"randomChallenge","allowCredentials":[{"type":"public-key","id":"credentialId","transports":["usb"]}],"userVerification":"preferred","status":"success","errorMessage":""}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testSerializationWithOnlyRequiredFields() {
        val options = PublicKeyCredentialRequestOptions(
            rpId = "example.com",
            timeout = 60000,
            challenge = "randomChallenge",
            userVerification = "preferred",
            status = "success",
            errorMessage = ""
        )

        val jsonString = json.encodeToString(PublicKeyCredentialRequestOptions.serializer(), options)
        val expectedJson = """{"rpId":"example.com","timeout":60000,"challenge":"randomChallenge","userVerification":"preferred","status":"success","errorMessage":""}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testDeserializationWithAllFields() {
        val jsonString = """{"rpId":"example.com","timeout":60000,"challenge":"randomChallenge","allowCredentials":[{"type":"public-key","id":"credentialId","transports":["usb"]}],"userVerification":"preferred","status":"success","errorMessage":""}"""
        val options = json.decodeFromString<PublicKeyCredentialRequestOptions>(jsonString)

        assertEquals("example.com", options.rpId)
        assertEquals(60000, options.timeout)
        assertEquals("randomChallenge", options.challenge)
        assertEquals(1, options.allowCredentials.size)
        assertEquals("credentialId", options.allowCredentials[0].id)
        assertEquals("public-key", options.allowCredentials[0].type.value)
        assertEquals("preferred", options.userVerification)
        assertEquals("success", options.status)
        assertEquals("", options.errorMessage)
    }

    @Test
    fun testDeserializationWithNullAllowCredentials() {
        val jsonString = """{"rpId":"example.com","timeout":60000,"challenge":"randomChallenge","userVerification":"preferred","status":"success","errorMessage":""}"""
        val options = json.decodeFromString<PublicKeyCredentialRequestOptions>(jsonString)

        assertEquals("example.com", options.rpId)
        assertEquals(60000, options.timeout)
        assertEquals("randomChallenge", options.challenge)
        assertTrue(options.allowCredentials.isEmpty())
        assertEquals("preferred", options.userVerification)
        assertEquals("success", options.status)
        assertEquals("", options.errorMessage)
    }

    @Test(expected = SerializationException::class)
    fun testDeserializationWithInvalidJson() {
        val jsonString = """{"rpId":123,"timeout":"notAnInt"}""" // Invalid types for fields
        json.decodeFromString<PublicKeyCredentialRequestOptions>(jsonString)
    }

    @Test
    fun testDeserializationWithEmptyFields() {
        val jsonString = """{"rpId":"","timeout":0,"challenge":"","userVerification":"","status":"","errorMessage":""}"""
        val options = json.decodeFromString<PublicKeyCredentialRequestOptions>(jsonString)

        assertEquals("", options.rpId)
        assertEquals(0, options.timeout)
        assertEquals("", options.challenge)
        assertEquals("", options.userVerification)
        assertEquals("", options.status)
        assertEquals("", options.errorMessage)
    }
}
