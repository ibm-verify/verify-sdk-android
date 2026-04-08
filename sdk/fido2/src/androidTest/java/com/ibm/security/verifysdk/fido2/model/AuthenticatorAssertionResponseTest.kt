package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
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
class AuthenticatorAssertionResponseTest{

    @Test
    fun testSerialization() {
        val responseAssertion = ResponseAssertion(
            clientDataJSON = """{"data":"exampleClientData"}""",
            authenticatorData = "authenticatorDataExample",
            signature = "signatureExample"
        )

        val authenticatorAssertionResponse = AuthenticatorAssertionResponse(
            id = "testId",
            rawId = "testRawId",
            response = responseAssertion,
            type = "public-key"
        )

        val jsonString = json.encodeToString(
            AuthenticatorAssertionResponse.serializer(),
            authenticatorAssertionResponse
        )
        val expectedJson =
            """{"id":"testId","rawId":"testRawId","response":{"clientDataJSON":"{\"data\":\"exampleClientData\"}","authenticatorData":"authenticatorDataExample","signature":"signatureExample"},"type":"public-key","nickname":"FIDO2App - Android"}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testDeserialization() {
        val jsonString = """{"id":"testId","rawId":"testRawId","response":{"clientDataJSON":"{\"data\":\"exampleClientData\"}","authenticatorData":"authenticatorDataExample","signature":"signatureExample"},"type":"public-key","nickname":"FIDO2App - Android"}"""
        val authenticatorAssertionResponse = json.decodeFromString(AuthenticatorAssertionResponse.serializer(), jsonString)

        assertEquals("testId", authenticatorAssertionResponse.id)
        assertEquals("testRawId", authenticatorAssertionResponse.rawId)
        assertEquals("public-key", authenticatorAssertionResponse.type)
        assertEquals("FIDO2App - Android", authenticatorAssertionResponse.nickname)
        assertEquals("{\"data\":\"exampleClientData\"}", authenticatorAssertionResponse.response.clientDataJSON)
        assertEquals("authenticatorDataExample", authenticatorAssertionResponse.response.authenticatorData)
        assertEquals("signatureExample", authenticatorAssertionResponse.response.signature)
    }

    @Test
    fun testEquality() {
        val responseAssertion = ResponseAssertion(
            clientDataJSON = """{"data":"exampleClientData"}""",
            authenticatorData = "authenticatorDataExample",
            signature = "signatureExample"
        )

        val response1 = AuthenticatorAssertionResponse(
            id = "testId",
            rawId = "testRawId",
            response = responseAssertion,
            type = "public-key"
        )

        val response2 = AuthenticatorAssertionResponse(
            id = "testId",
            rawId = "testRawId",
            response = responseAssertion,
            type = "public-key"
        )

        assertEquals(response1, response2)
    }
}
