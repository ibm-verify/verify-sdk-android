package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.MissingFieldException
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

@OptIn(ExperimentalSerializationApi::class)
@RunWith(AndroidJUnit4::class)
class AuthenticatorAttestationResponseTest {

    @Test
    fun testSerializationWithAllFields() {
        val responseAttestation = ResponseAttestation(
            clientDataJSON = """{"type":"webauthn.create","challenge":"randomChallenge"}""",
            attestationObject = """{"fmt":"none","authData":"authDataValue"}"""
        )
        val authResponse = AuthenticatorAttestationResponse(
            id = "testId",
            rawId = "testRawId",
            response = responseAttestation,
            type = "public-key"
        )

        val jsonString =
            json.encodeToString(AuthenticatorAttestationResponse.serializer(), authResponse)
        val expectedJson = """
            {
                "id":"testId",
                "rawId":"testRawId",
                "response":{
                    "clientDataJSON":"{\"type\":\"webauthn.create\",\"challenge\":\"randomChallenge\"}",
                    "attestationObject":"{\"fmt\":\"none\",\"authData\":\"authDataValue\"}"
                },
                "type":"public-key",
                "nickname":"FIDO2App-Android"
            }
        """.trimIndent().replace("\n", "").replace(" ", "")
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testDeserializationWithAllFields() {
        val jsonString = """
            {
                "id":"testId",
                "rawId":"testRawId",
                "response":{
                    "clientDataJSON":"{\"type\":\"webauthn.create\",\"challenge\":\"randomChallenge\"}",
                    "attestationObject":"{\"fmt\":\"none\",\"authData\":\"authDataValue\"}"
                },
                "type":"public-key",
                "nickname":"FIDO2App-Android"
            }
        """.trimIndent().replace("\n", "").replace(" ", "")
        val authResponse = json.decodeFromString<AuthenticatorAttestationResponse>(jsonString)

        assertEquals("testId", authResponse.id)
        assertEquals("testRawId", authResponse.rawId)
        assertEquals(
            """{"type":"webauthn.create","challenge":"randomChallenge"}""",
            authResponse.response.clientDataJSON
        )
        assertEquals(
            """{"fmt":"none","authData":"authDataValue"}""",
            authResponse.response.attestationObject
        )
        assertEquals("public-key", authResponse.type)
        assertEquals("FIDO2App-Android", authResponse.nickname)
    }

    @Test
    fun testSerializationWithDefaultNickname() {
        val responseAttestation = ResponseAttestation(
            clientDataJSON = """{"type":"webauthn.create","challenge":"randomChallenge"}""",
            attestationObject = """{"fmt":"none","authData":"authDataValue"}"""
        )
        val authResponse = AuthenticatorAttestationResponse(
            id = "testId",
            rawId = "testRawId",
            response = responseAttestation,
            type = "public-key"
        )

        val jsonString =
            json.encodeToString(AuthenticatorAttestationResponse.serializer(), authResponse)
        val expectedJson = """
            {
                "id":"testId",
                "rawId":"testRawId",
                "response":{
                    "clientDataJSON":"{\"type\":\"webauthn.create\",\"challenge\":\"randomChallenge\"}",
                    "attestationObject":"{\"fmt\":\"none\",\"authData\":\"authDataValue\"}"
                },
                "type":"public-key",
                "nickname":"FIDO2App-Android"
            }
        """.trimIndent().replace("\n", "").replace(" ", "")
        assertTrue(jsonString.contains("nickname\":\"FIDO2App-Android"))
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testSerializationWithCustomNickname() {
        val responseAttestation = ResponseAttestation(
            clientDataJSON = """{"type":"webauthn.create","challenge":"randomChallenge"}""",
            attestationObject = """{"fmt":"none","authData":"authDataValue"}"""
        )
        val authResponse = AuthenticatorAttestationResponse(
            id = "testId",
            rawId = "testRawId",
            response = responseAttestation,
            type = "public-key",
            nickname = "CustomNickname"
        )

        val jsonString =
            json.encodeToString(AuthenticatorAttestationResponse.serializer(), authResponse)
        val expectedJson = """
            {
                "id":"testId",
                "rawId":"testRawId",
                "response":{
                    "clientDataJSON":"{\"type\":\"webauthn.create\",\"challenge\":\"randomChallenge\"}",
                    "attestationObject":"{\"fmt\":\"none\",\"authData\":\"authDataValue\"}"
                },
                "type":"public-key",
                "nickname":"CustomNickname"
            }
        """.trimIndent().replace("\n", "").replace(" ", "")
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testDeserializationWithCustomNickname() {
        val jsonString = """
            {
                "id":"testId",
                "rawId":"testRawId",
                "response":{
                    "clientDataJSON":"{\"type\":\"webauthn.create\",\"challenge\":\"randomChallenge\"}",
                    "attestationObject":"{\"fmt\":\"none\",\"authData\":\"authDataValue\"}"
                },
                "type":"public-key",
                "nickname":"CustomNickname"
            }
        """.trimIndent().replace("\n", "").replace(" ", "")
        val authResponse = json.decodeFromString<AuthenticatorAttestationResponse>(jsonString)

        assertEquals("testId", authResponse.id)
        assertEquals("testRawId", authResponse.rawId)
        assertEquals(
            """{"type":"webauthn.create","challenge":"randomChallenge"}""",
            authResponse.response.clientDataJSON
        )
        assertEquals(
            """{"fmt":"none","authData":"authDataValue"}""",
            authResponse.response.attestationObject
        )
        assertEquals("public-key", authResponse.type)
        assertEquals("CustomNickname", authResponse.nickname)
    }

    @Test
    fun testDeserializationWithMissingNickname() {
        val jsonString = """
            {
                "id":"testId",
                "rawId":"testRawId",
                "response":{
                    "clientDataJSON":"{\"type\":\"webauthn.create\",\"challenge\":\"randomChallenge\"}",
                    "attestationObject":"{\"fmt\":\"none\",\"authData\":\"authDataValue\"}"
                },
                "type":"public-key"
            }
        """.trimIndent().replace("\n", "").replace(" ", "")
        val authResponse = json.decodeFromString<AuthenticatorAttestationResponse>(jsonString)

        assertEquals("FIDO2App-Android", authResponse.nickname)
    }

    @Test(expected = MissingFieldException::class)
    fun testDeserializationWithInvalidJson() {
        val jsonString = """{"id":123,"rawId":true}"""
        json.decodeFromString<AuthenticatorAttestationResponse>(jsonString)
    }
}
