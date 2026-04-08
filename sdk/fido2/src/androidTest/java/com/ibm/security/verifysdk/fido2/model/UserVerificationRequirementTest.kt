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
class UserVerificationRequirementTest {

    @Test
    fun testEnumValue() {
        val requirement = UserVerificationRequirement.REQUIRED
        assertEquals("required", requirement.value)
    }

    @Test
    fun testEnumSerialization() {
        val requirement = UserVerificationRequirement.PREFERRED
        val jsonString = json.encodeToString(UserVerificationRequirement.serializer(), requirement)
        val expectedJson = """"preferred""""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testEnumDeserialization() {
        val jsonString = """"discouraged""""
        val requirement = json.decodeFromString(UserVerificationRequirement.serializer(), jsonString)
        assertEquals(UserVerificationRequirement.DISCOURAGED, requirement)
    }

    @Test(expected = SerializationException::class)
    fun testEnumDeserialization_invalidValue() {
        val jsonString = """"invalid-requirement""""
        json.decodeFromString(UserVerificationRequirement.serializer(), jsonString)
    }

    @Test
    fun testEnumValues() {
        val expectedValues = listOf(
            UserVerificationRequirement.REQUIRED,
            UserVerificationRequirement.PREFERRED,
            UserVerificationRequirement.DISCOURAGED
        )
        val actualValues = UserVerificationRequirement.values().toList()
        assertEquals(expectedValues, actualValues)
    }

    @Test
    fun testEnumValueOf() {
        val requirement = UserVerificationRequirement.valueOf("PREFERRED")
        assertEquals(UserVerificationRequirement.PREFERRED, requirement)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testEnumValueOf_invalidName() {
        UserVerificationRequirement.valueOf("INVALID_NAME")
    }
}
