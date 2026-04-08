package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
class PublicKeyCredentialCreationOptionsTest {

    @Test
    fun testDefaultValues() {
        val rpEntity = PublicKeyCredentialRpEntity("test_id", "Test RP")
        val userEntity = PublicKeyCredentialUserEntity("test_user_id", "Test User", "Test Name")
        val options = PublicKeyCredentialCreationOptions(
            rp = rpEntity,
            user = userEntity,
            challenge = "challenge_string",
            timeout = 30000,
            authenticatorSelection = AuthenticatorSelectionCriteria()
        )

        assertEquals(AttestationConveyancePreference.NONE, options.attestation)
        assertTrue(options.pubKeyCredParams.isEmpty())
        assertTrue(options.excludeCredentials.isEmpty())
        assertNull(options.extension)
    }

    @Test
    fun testCustomValues() {
        val rpEntity = PublicKeyCredentialRpEntity("test_id", "Test RP")
        val userEntity = PublicKeyCredentialUserEntity("test_user_id", "Test User", "Test Name")
        val pubKeyCredParams = arrayListOf(
            PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7)
        )
        val excludeCredentials: ArrayList<PublicKeyCredentialDescriptor> = arrayListOf(
            PublicKeyCredentialDescriptor(
                type = PublicKeyCredentialType.PUBLIC_KEY,
                id = "test_id"
            )
        )
        val options = PublicKeyCredentialCreationOptions(
            rp = rpEntity,
            user = userEntity,
            challenge = "challenge_string",
            pubKeyCredParams = pubKeyCredParams,
            timeout = 30000,
            excludeCredentials = excludeCredentials,
            authenticatorSelection = AuthenticatorSelectionCriteria(),
            attestation = AttestationConveyancePreference.DIRECT,
            extension = mapOf("example" to JsonObject(mapOf()))
        )

        assertEquals(AttestationConveyancePreference.DIRECT, options.attestation)
        assertEquals(1, options.pubKeyCredParams.size)
        assertEquals(1, options.excludeCredentials.size)
        assertNotNull(options.extension)
    }

    @Test
    fun testSerialization() {
        val rpEntity = PublicKeyCredentialRpEntity("test_id", "Test RP")
        val userEntity = PublicKeyCredentialUserEntity("test_user_id", "Test User", "Test Name")
        val options = PublicKeyCredentialCreationOptions(
            rp = rpEntity,
            user = userEntity,
            challenge = "challenge_string",
            timeout = 30000,
            authenticatorSelection = AuthenticatorSelectionCriteria()
        )

        val jsonString =
            json.encodeToString(PublicKeyCredentialCreationOptions.serializer(), options)
        val expectedJson =
            """{"rp":{"id":"test_id","name":"Test RP"},"user":{"id":"test_user_id","displayName":"Test User","name":"Test Name"},"challenge":"challenge_string","timeout":30000,"authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":false,"userVerification":"preferred"},"attestation":"none"}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testDeserialization() {
        val jsonString =
            """{"rp":{"id":"test_id","name":"Test RP"},"user":{"id":"test_user_id","displayName":"Test User","name":"Test Name"},"challenge":"challenge_string","timeout":30000,"authenticatorSelection":{"authenticatorAttachment":"platform","requireResidentKey":false,"userVerification":"preferred"},"attestation":"none"}"""
        val options = json.decodeFromString<PublicKeyCredentialCreationOptions>(jsonString)

        assertEquals("test_id", options.rp.id)
        assertEquals("Test RP", options.rp.name)
        assertEquals("test_user_id", options.user.id)
        assertEquals("Test User", options.user.displayName)
        assertEquals("challenge_string", options.challenge)
        assertEquals(30000, options.timeout)
        assertEquals(AttestationConveyancePreference.NONE, options.attestation)
    }

    @Test(expected = SerializationException::class)
    fun testDeserialization_invalidValue() {
        val jsonString =
            """{"rp":{"id":"test_id","name":"Test RP"},"user":{"id":"test_user_id","displayName":"Test User","name":"Test Name"},"challenge":"challenge_string","timeout":30000,"authenticatorSelection":{"authenticatorAttachment":"invalid","requireResidentKey":false,"userVerification":"preferred"},"attestation":"none"}"""
        json.decodeFromString<PublicKeyCredentialCreationOptions>(jsonString)
    }
}
