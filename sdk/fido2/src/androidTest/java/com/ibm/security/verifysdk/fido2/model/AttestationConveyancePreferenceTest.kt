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
class AttestationConveyancePreferenceTest {

    @Test
    fun testEnumValue() {
        val preference = AttestationConveyancePreference.NONE
        assertEquals("none", preference.value)
    }

    @Test
    fun testEnumSerialization() {
        val preference = AttestationConveyancePreference.INDIRECT
        val jsonString = json.encodeToString(AttestationConveyancePreference.serializer(), preference)
        val expectedJson = """"indirect""""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testEnumDeserialization() {
        val jsonString = """"direct""""
        val preference = json.decodeFromString(AttestationConveyancePreference.serializer(), jsonString)
        assertEquals(AttestationConveyancePreference.DIRECT, preference)
    }

    @Test(expected = SerializationException::class)
    fun testEnumDeserialization_invalidValue() {
        val jsonString = """"invalid-preference""""
        json.decodeFromString(AttestationConveyancePreference.serializer(), jsonString)
    }

    @Test
    fun testEnumValues() {
        val expectedValues = listOf(
            AttestationConveyancePreference.NONE,
            AttestationConveyancePreference.INDIRECT,
            AttestationConveyancePreference.DIRECT
        )
        val actualValues = AttestationConveyancePreference.values().toList()
        assertEquals(expectedValues, actualValues)
    }

    @Test
    fun testEnumValueOf() {
        val preference = AttestationConveyancePreference.valueOf("INDIRECT")
        assertEquals(AttestationConveyancePreference.INDIRECT, preference)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testEnumValueOf_invalidName() {
        AttestationConveyancePreference.valueOf("INVALID_NAME")
    }
}
