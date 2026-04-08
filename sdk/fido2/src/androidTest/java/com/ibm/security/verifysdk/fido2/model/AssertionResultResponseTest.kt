package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
class AssertionResultResponseTest {

    @Test
    fun testSerializationWithAllFields() {
        val additionalData =
            mapOf("key1" to JsonPrimitive("value1"), "key2" to JsonPrimitive("value2"))
        val response = AssertionResultResponse(
            errorMessage = "An error occurred",
            status = "failed",
            additionalData = additionalData
        )

        val jsonString = json.encodeToString(AssertionResultResponse.serializer(), response)
        val expectedJson =
            """{"errorMessage":"An error occurred","status":"failed","key1":"value1","key2":"value2"}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testSerializationWithOnlyErrorMessage() {
        val response = AssertionResultResponse(
            errorMessage = "An error occurred"
        )

        val jsonString = json.encodeToString(AssertionResultResponse.serializer(), response)
        val expectedJson = """{"errorMessage":"An error occurred"}"""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testSerializationWithOnlyStatus() {
        val response = AssertionResultResponse(
            status = "success"
        )

        val jsonString = json.encodeToString(AssertionResultResponse.serializer(), response)
        val expectedJson = """{"status":"success"}"""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testSerializationWithAdditionalDataOnly() {
        val additionalData = mapOf("key1" to JsonPrimitive("value1"))
        val response = AssertionResultResponse(
            additionalData = additionalData
        )

        val jsonString = json.encodeToString(AssertionResultResponse.serializer(), response)
        val expectedJson = """{"key1":"value1"}"""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testDeserializationWithAllFields() {
        val jsonString =
            """{"errorMessage":"An error occurred","status":"failed","key1":"value1","key2":"value2"}"""
        val response = json.decodeFromString<AssertionResultResponse>(jsonString)

        assertEquals("An error occurred", response.errorMessage)
        assertEquals("failed", response.status)
        assertNotNull(response.additionalData)
        assertEquals(2, response.additionalData?.size)
        assertEquals(JsonPrimitive("value1"), response.additionalData?.get("key1"))
        assertEquals(JsonPrimitive("value2"), response.additionalData?.get("key2"))
    }

    @Test
    fun testDeserializationWithNullFields() {
        val jsonString = """{}"""
        val response = json.decodeFromString<AssertionResultResponse>(jsonString)

        assertNull(response.errorMessage)
        assertNull(response.status)
        assertEquals(0, response.additionalData!!.size)
    }

    @Test
    fun testDeserializationWithMissingKnownKeys() {
        val jsonString = """{"key1":"value1"}"""
        val response = json.decodeFromString(AssertionResultResponse.serializer(), jsonString)

        assertNull(response.errorMessage)
        assertNull(response.status)
        assertNotNull(response.additionalData)
        assertEquals(1, response.additionalData?.size)
        assertEquals(JsonPrimitive("value1"), response.additionalData?.get("key1"))
    }

    @Test
    fun testDeserializationWithNumericValue() {
        val jsonString = """{"errorMessage":123}""" // Invalid type for errorMessage
        val response = json.decodeFromString(AssertionResultResponse.serializer(), jsonString)
        assertEquals("123", response.errorMessage)
    }
}
