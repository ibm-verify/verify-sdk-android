/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.core.serializer.InstantIsoSerializer
import com.ibm.security.verifysdk.core.serializer.URLSerializer
import com.ibm.security.verifysdk.core.serializer.UUIDSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import java.util.UUID
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Basic test cases for custom serializers.
 */
@RunWith(AndroidJUnit4::class)
class SerializersTest {

    // URLSerializer Tests
    
    @Test
    fun testURLSerializerSerialize() {
        val url = URL("https://example.com/api/v1")
        val json = Json.encodeToJsonElement(URLSerializer, url)
        
        assertEquals("https://example.com/api/v1", json.jsonPrimitive.content)
    }

    @Test
    fun testURLSerializerDeserialize() {
        val jsonElement = JsonPrimitive("https://example.com/api/v1")
        val url = Json.decodeFromJsonElement(URLSerializer, jsonElement)
        
        assertEquals("https://example.com/api/v1", url.toString())
    }

    @Test
    fun testURLSerializerRoundTrip() {
        val original = URL("https://example.com:8443/path?query=value#fragment")
        val json = Json.encodeToJsonElement(URLSerializer, original)
        val deserialized = Json.decodeFromJsonElement(URLSerializer, json)
        
        assertEquals(original.toString(), deserialized.toString())
    }

    @Test
    fun testURLSerializerWithPort() {
        val url = URL("https://example.com:8443/api")
        val json = Json.encodeToJsonElement(URLSerializer, url)
        val deserialized = Json.decodeFromJsonElement(URLSerializer, json)
        
        assertEquals(8443, deserialized.port)
    }

    // UUIDSerializer Tests
    
    @Test
    fun testUUIDSerializerSerialize() {
        val uuid = UUID.fromString("550e8400-e29b-41d4-a716-446655440000")
        val jsonString = Json.encodeToString(UUIDSerializer, uuid)
        
        assertEquals("\"550e8400-e29b-41d4-a716-446655440000\"", jsonString)
    }

    @Test
    fun testUUIDSerializerDeserialize() {
        val jsonString = "\"550e8400-e29b-41d4-a716-446655440000\""
        val uuid = Json.decodeFromString(UUIDSerializer, jsonString)
        
        assertEquals("550e8400-e29b-41d4-a716-446655440000", uuid.toString())
    }

    @Test
    fun testUUIDSerializerRoundTrip() {
        val original = UUID.randomUUID()
        val jsonString = Json.encodeToString(UUIDSerializer, original)
        val deserialized = Json.decodeFromString(UUIDSerializer, jsonString)
        
        assertEquals(original, deserialized)
    }

    @Test
    fun testUUIDSerializerRandomUUID() {
        val uuid1 = UUID.randomUUID()
        val uuid2 = UUID.randomUUID()
        
        assertNotEquals(uuid1, uuid2)
        
        val json1 = Json.encodeToString(UUIDSerializer, uuid1)
        val json2 = Json.encodeToString(UUIDSerializer, uuid2)
        
        assertNotEquals(json1, json2)
    }

    // InstantIsoSerializer Tests
    
    @OptIn(ExperimentalTime::class)
    @Test
    fun testInstantSerializerSerialize() {
        val instant = Instant.parse("2026-03-31T00:00:00Z")
        val json = Json.encodeToJsonElement(InstantIsoSerializer, instant)
        
        assertTrue(json.jsonPrimitive.content.contains("2026-03-31"))
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun testInstantSerializerDeserialize() {
        val jsonElement = JsonPrimitive("2026-03-31T12:30:45.123Z")
        val instant = Json.decodeFromJsonElement(InstantIsoSerializer, jsonElement)
        
        assertNotNull(instant)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun testInstantSerializerRoundTrip() {
        val original = Instant.parse("2026-03-31T12:30:45.123Z")
        val json = Json.encodeToJsonElement(InstantIsoSerializer, original)
        val deserialized = Json.decodeFromJsonElement(InstantIsoSerializer, json)
        
        assertEquals(original.toString(), deserialized.toString())
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun testInstantSerializerISOFormat() {
        val instant = Instant.parse("2026-03-31T12:30:45Z")
        val json = Json.encodeToJsonElement(InstantIsoSerializer, instant)
        val serialized = json.jsonPrimitive.content
        
        // Should be in ISO-8601 format
        assertTrue(serialized.matches(Regex("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}.*Z")))
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun testInstantSerializerWithMilliseconds() {
        val jsonElement = JsonPrimitive("2026-03-31T12:30:45.123456789Z")
        val instant = Json.decodeFromJsonElement(InstantIsoSerializer, jsonElement)
        
        assertNotNull(instant)
    }

    // Descriptor Tests
    
    @Test
    fun testURLSerializerDescriptor() {
        val descriptor = URLSerializer.descriptor
        
        assertEquals("URL", descriptor.serialName)
    }

    @Test
    fun testUUIDSerializerDescriptor() {
        val descriptor = UUIDSerializer.descriptor
        
        assertNotNull(descriptor)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun testInstantSerializerDescriptor() {
        val descriptor = InstantIsoSerializer.descriptor
        
        assertEquals("Instant", descriptor.serialName)
    }
}

