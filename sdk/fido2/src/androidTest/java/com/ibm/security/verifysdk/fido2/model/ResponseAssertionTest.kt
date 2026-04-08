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
class ResponseAssertionTest {

    @Test
    fun testSerialization() {
        val responseAssertion = ResponseAssertion(
            clientDataJSON = """{"data":"exampleClientData"}""",
            authenticatorData = "authenticatorDataExample",
            signature = "signatureExample"
        )

        val jsonString = json.encodeToString(ResponseAssertion.serializer(), responseAssertion)
        val expectedJson = """{"clientDataJSON":"{\"data\":\"exampleClientData\"}","authenticatorData":"authenticatorDataExample","signature":"signatureExample"}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testDeserialization() {
        val jsonString = """{"clientDataJSON":"{\"data\":\"exampleClientData\"}","authenticatorData":"authenticatorDataExample","signature":"signatureExample"}"""
        val responseAssertion = json.decodeFromString(ResponseAssertion.serializer(), jsonString)

        assertEquals("{\"data\":\"exampleClientData\"}", responseAssertion.clientDataJSON)
        assertEquals("authenticatorDataExample", responseAssertion.authenticatorData)
        assertEquals("signatureExample", responseAssertion.signature)
    }

    @Test
    fun testEquality() {
        val responseAssertion1 = ResponseAssertion(
            clientDataJSON = """{"data":"exampleClientData"}""",
            authenticatorData = "authenticatorDataExample",
            signature = "signatureExample"
        )

        val responseAssertion2 = ResponseAssertion(
            clientDataJSON = """{"data":"exampleClientData"}""",
            authenticatorData = "authenticatorDataExample",
            signature = "signatureExample"
        )

        assertEquals(responseAssertion1, responseAssertion2)
    }
}
