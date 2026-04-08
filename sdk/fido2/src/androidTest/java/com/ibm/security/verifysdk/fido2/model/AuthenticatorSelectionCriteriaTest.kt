package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
class AuthenticatorSelectionCriteriaTest {

    @Test
    fun testDefaultValues() {
        val criteria = AuthenticatorSelectionCriteria()

        assertEquals(AuthenticatorAttachment.PLATFORM, criteria.authenticatorAttachment)
        assertFalse(criteria.requireResidentKey)
        assertEquals(UserVerificationRequirement.PREFERRED, criteria.userVerification)
    }

    @Test
    fun testCustomValues() {
        val customCriteria = AuthenticatorSelectionCriteria(
            authenticatorAttachment = AuthenticatorAttachment.CROSS_PLATFORM,
            requireResidentKey = true,
            userVerification = UserVerificationRequirement.REQUIRED
        )

        assertEquals(AuthenticatorAttachment.CROSS_PLATFORM, customCriteria.authenticatorAttachment)
        assertTrue(customCriteria.requireResidentKey)
        assertEquals(UserVerificationRequirement.REQUIRED, customCriteria.userVerification)
    }

    @Test
    fun testSerialization() {
        val criteria = AuthenticatorSelectionCriteria(
            authenticatorAttachment = AuthenticatorAttachment.CROSS_PLATFORM,
            requireResidentKey = true,
            userVerification = UserVerificationRequirement.REQUIRED
        )

        val jsonString = json.encodeToString(AuthenticatorSelectionCriteria.serializer(), criteria)
        val expectedJson = """{"authenticatorAttachment":"cross-platform","requireResidentKey":true,"userVerification":"required"}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testDeserialization() {
        val jsonString = """{"authenticatorAttachment":"platform","requireResidentKey":false,"userVerification":"preferred"}"""
        val criteria = json.decodeFromString(AuthenticatorSelectionCriteria.serializer(), jsonString)

        assertEquals(AuthenticatorAttachment.PLATFORM, criteria.authenticatorAttachment)
        assertFalse(criteria.requireResidentKey)
        assertEquals(UserVerificationRequirement.PREFERRED, criteria.userVerification)
    }
}
