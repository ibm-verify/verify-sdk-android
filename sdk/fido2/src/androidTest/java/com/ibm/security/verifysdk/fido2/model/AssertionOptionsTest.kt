package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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
class AssertionOptionsTest {

    @Test
    fun testSerialization() {
        val assertionOptions = AssertionOptions(
            username = "testUser",
            userVerification = "preferred"
        )

        val jsonString = json.encodeToString(AssertionOptions.serializer(), assertionOptions)
        val expectedJson = """{"username":"testUser","userVerification":"preferred"}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testDeserialization() {
        val jsonString = """{"username":"testUser","userVerification":"preferred"}"""
        val assertionOptions = json.decodeFromString(AssertionOptions.serializer(), jsonString)

        assertEquals("testUser", assertionOptions.username)
        assertEquals("preferred", assertionOptions.userVerification)
    }

    @Test
    fun testEquality() {
        val assertionOptions1 = AssertionOptions(
            username = "testUser",
            userVerification = "preferred"
        )

        val assertionOptions2 = AssertionOptions(
            username = "testUser",
            userVerification = "preferred"
        )

        assertEquals(assertionOptions1, assertionOptions2)
    }

    @Test
    fun testInequality() {
        val assertionOptions1 = AssertionOptions(
            username = "testUser",
            userVerification = "preferred"
        )

        val assertionOptions2 = AssertionOptions(
            username = "differentUser",
            userVerification = "required"
        )

        assertNotEquals(assertionOptions1, assertionOptions2)
    }
}
