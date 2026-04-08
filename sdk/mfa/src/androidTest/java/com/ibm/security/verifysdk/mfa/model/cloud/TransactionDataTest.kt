/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.cloud

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Comprehensive test suite for TransactionData and AdditionalDataItem.
 *
 * Tests verify:
 * 1. JSON serialization and deserialization
 * 2. Null safety for optional fields
 * 3. Handling of missing fields
 * 4. Complex nested structures
 * 5. Edge cases (empty strings, special characters)
 * 6. Type safety with kotlinx.serialization
 * 7. Well-known field handling (type, originLocation, imageURL, denyReasonEnabled)
 * 8. Custom data preservation
 */
@RunWith(AndroidJUnit4::class)
class TransactionDataTest {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    /**
     * Test deserialization of complete TransactionData with all fields.
     */
    @Test
    fun testCompleteTransactionDataDeserialization() {
        val jsonString = """
            {
                "message": "Login attempt from new device",
                "originIpAddress": "192.168.1.100",
                "originUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "additionalData": [
                    {"name": "type", "value": "Login"},
                    {"name": "originLocation", "value": "New York, USA"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals("Login attempt from new device", transactionData.message)
        assertEquals("192.168.1.100", transactionData.originIpAddress)
        assertEquals("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", transactionData.originUserAgent)
        assertNotNull(transactionData.additionalData)
        assertEquals(2, transactionData.additionalData?.size)
    }

    /**
     * Test deserialization with minimal fields (all optional fields null).
     */
    @Test
    fun testMinimalTransactionDataDeserialization() {
        val jsonString = "{}"

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNull("Message should be null", transactionData.message)
        assertNull("IP address should be null", transactionData.originIpAddress)
        assertNull("User agent should be null", transactionData.originUserAgent)
        assertNull("Additional data should be null", transactionData.additionalData)
    }

    /**
     * Test deserialization with only message field.
     */
    @Test
    fun testTransactionDataWithOnlyMessage() {
        val jsonString = """{"message": "Test message"}"""

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals("Test message", transactionData.message)
        assertNull(transactionData.originIpAddress)
        assertNull(transactionData.originUserAgent)
        assertNull(transactionData.additionalData)
    }

    /**
     * Test deserialization with only IP address.
     */
    @Test
    fun testTransactionDataWithOnlyIpAddress() {
        val jsonString = """{"originIpAddress": "10.0.0.1"}"""

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNull(transactionData.message)
        assertEquals("10.0.0.1", transactionData.originIpAddress)
        assertNull(transactionData.originUserAgent)
        assertNull(transactionData.additionalData)
    }

    /**
     * Test deserialization with only user agent.
     */
    @Test
    fun testTransactionDataWithOnlyUserAgent() {
        val jsonString = """{"originUserAgent": "Chrome/91.0"}"""

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNull(transactionData.message)
        assertNull(transactionData.originIpAddress)
        assertEquals("Chrome/91.0", transactionData.originUserAgent)
        assertNull(transactionData.additionalData)
    }

    /**
     * Test deserialization with empty additional data array.
     */
    @Test
    fun testTransactionDataWithEmptyAdditionalData() {
        val jsonString = """{"additionalData": []}"""

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNotNull(transactionData.additionalData)
        assertTrue("Additional data should be empty", transactionData.additionalData!!.isEmpty())
    }

    /**
     * Test deserialization with multiple additional data items.
     */
    @Test
    fun testTransactionDataWithMultipleAdditionalDataItems() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "type", "value": "Payment"},
                    {"name": "amount", "value": "100.00"},
                    {"name": "currency", "value": "USD"},
                    {"name": "merchant", "value": "Example Store"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNotNull(transactionData.additionalData)
        assertEquals(4, transactionData.additionalData?.size)
        
        val items = transactionData.additionalData!!
        assertEquals("type", items[0].name)
        assertEquals("Payment", items[0].value)
        assertEquals("amount", items[1].name)
        assertEquals("100.00", items[1].value)
        assertEquals("currency", items[2].name)
        assertEquals("USD", items[2].value)
        assertEquals("merchant", items[3].name)
        assertEquals("Example Store", items[3].value)
    }

    /**
     * Test well-known additional data field: type.
     */
    @Test
    fun testWellKnownFieldType() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "type", "value": "Login"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        val typeItem = transactionData.additionalData?.find { it.name == "type" }
        assertNotNull("Type field should exist", typeItem)
        assertEquals("Login", typeItem?.value)
    }

    /**
     * Test well-known additional data field: originLocation.
     */
    @Test
    fun testWellKnownFieldOriginLocation() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "originLocation", "value": "San Francisco, CA"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        val locationItem = transactionData.additionalData?.find { it.name == "originLocation" }
        assertNotNull("Location field should exist", locationItem)
        assertEquals("San Francisco, CA", locationItem?.value)
    }

    /**
     * Test well-known additional data field: imageURL.
     */
    @Test
    fun testWellKnownFieldImageURL() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "imageURL", "value": "https://example.com/image.png"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        val imageItem = transactionData.additionalData?.find { it.name == "imageURL" }
        assertNotNull("Image URL field should exist", imageItem)
        assertEquals("https://example.com/image.png", imageItem?.value)
    }

    /**
     * Test well-known additional data field: denyReasonEnabled.
     */
    @Test
    fun testWellKnownFieldDenyReasonEnabled() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "denyReasonEnabled", "value": "true"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        val denyReasonItem = transactionData.additionalData?.find { it.name == "denyReasonEnabled" }
        assertNotNull("Deny reason field should exist", denyReasonItem)
        assertEquals("true", denyReasonItem?.value)
    }

    /**
     * Test all well-known fields together.
     */
    @Test
    fun testAllWellKnownFields() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "type", "value": "Payment"},
                    {"name": "originLocation", "value": "London, UK"},
                    {"name": "imageURL", "value": "https://example.com/logo.png"},
                    {"name": "denyReasonEnabled", "value": "false"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNotNull(transactionData.additionalData)
        assertEquals(4, transactionData.additionalData?.size)

        val items = transactionData.additionalData!!
        assertTrue(items.any { it.name == "type" && it.value == "Payment" })
        assertTrue(items.any { it.name == "originLocation" && it.value == "London, UK" })
        assertTrue(items.any { it.name == "imageURL" && it.value == "https://example.com/logo.png" })
        assertTrue(items.any { it.name == "denyReasonEnabled" && it.value == "false" })
    }

    /**
     * Test custom data fields (not well-known).
     */
    @Test
    fun testCustomDataFields() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "customField1", "value": "customValue1"},
                    {"name": "customField2", "value": "customValue2"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        val customItems = transactionData.additionalData?.filter { 
            it.name !in listOf("type", "originLocation", "imageURL", "denyReasonEnabled")
        }

        assertNotNull(customItems)
        assertEquals(2, customItems?.size)
        assertTrue(customItems!!.any { it.name == "customField1" && it.value == "customValue1" })
        assertTrue(customItems.any { it.name == "customField2" && it.value == "customValue2" })
    }

    /**
     * Test mixed well-known and custom fields.
     */
    @Test
    fun testMixedWellKnownAndCustomFields() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "type", "value": "Transfer"},
                    {"name": "accountNumber", "value": "1234567890"},
                    {"name": "originLocation", "value": "Tokyo, Japan"},
                    {"name": "transactionId", "value": "TXN-12345"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNotNull(transactionData.additionalData)
        assertEquals(4, transactionData.additionalData?.size)

        val wellKnown = transactionData.additionalData?.filter { 
            it.name in listOf("type", "originLocation", "imageURL", "denyReasonEnabled")
        }
        val custom = transactionData.additionalData?.filter { 
            it.name !in listOf("type", "originLocation", "imageURL", "denyReasonEnabled")
        }

        assertEquals(2, wellKnown?.size)
        assertEquals(2, custom?.size)
    }

    /**
     * Test serialization of TransactionData.
     */
    @Test
    fun testTransactionDataSerialization() {
        val transactionData = TransactionData(
            message = "Test message",
            originIpAddress = "192.168.1.1",
            originUserAgent = "TestAgent/1.0",
            additionalData = listOf(
                AdditionalDataItem("type", "Login"),
                AdditionalDataItem("custom", "value")
            )
        )

        val jsonString = json.encodeToString(transactionData)

        assertTrue(jsonString.contains("\"message\":\"Test message\""))
        assertTrue(jsonString.contains("\"originIpAddress\":\"192.168.1.1\""))
        assertTrue(jsonString.contains("\"originUserAgent\":\"TestAgent/1.0\""))
        assertTrue(jsonString.contains("\"additionalData\""))
    }

    /**
     * Test round-trip serialization/deserialization.
     */
    @Test
    fun testRoundTripSerialization() {
        val original = TransactionData(
            message = "Round trip test",
            originIpAddress = "10.0.0.1",
            originUserAgent = "TestBrowser/2.0",
            additionalData = listOf(
                AdditionalDataItem("type", "Payment"),
                AdditionalDataItem("amount", "50.00")
            )
        )

        val jsonString = json.encodeToString(original)
        val deserialized = json.decodeFromString<TransactionData>(jsonString)

        assertEquals(original.message, deserialized.message)
        assertEquals(original.originIpAddress, deserialized.originIpAddress)
        assertEquals(original.originUserAgent, deserialized.originUserAgent)
        assertEquals(original.additionalData?.size, deserialized.additionalData?.size)
    }

    /**
     * Test handling of special characters in message.
     */
    @Test
    fun testSpecialCharactersInMessage() {
        val jsonString = """
            {
                "message": "Login from \"New Device\" with special chars: <>&'\""
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals("Login from \"New Device\" with special chars: <>&'\"", transactionData.message)
    }

    /**
     * Test handling of Unicode characters.
     */
    @Test
    fun testUnicodeCharacters() {
        val jsonString = """
            {
                "message": "支付请求 - Payment Request 🔒",
                "originIpAddress": "192.168.1.1"
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals("支付请求 - Payment Request 🔒", transactionData.message)
    }

    /**
     * Test handling of very long strings.
     */
    @Test
    fun testLongStrings() {
        val longMessage = "A".repeat(1000)
        val jsonString = """{"message": "$longMessage"}"""

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals(1000, transactionData.message?.length)
        assertEquals(longMessage, transactionData.message)
    }

    /**
     * Test handling of empty strings.
     */
    @Test
    fun testEmptyStrings() {
        val jsonString = """
            {
                "message": "",
                "originIpAddress": "",
                "originUserAgent": ""
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals("", transactionData.message)
        assertEquals("", transactionData.originIpAddress)
        assertEquals("", transactionData.originUserAgent)
    }

    /**
     * Test handling of whitespace-only strings.
     */
    @Test
    fun testWhitespaceStrings() {
        val jsonString = """
            {
                "message": "   ",
                "originIpAddress": "\t\n"
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals("   ", transactionData.message)
        assertEquals("\t\n", transactionData.originIpAddress)
    }

    /**
     * Test handling of IPv6 addresses.
     */
    @Test
    fun testIpv6Address() {
        val jsonString = """{"originIpAddress": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}"""

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals("2001:0db8:85a3:0000:0000:8a2e:0370:7334", transactionData.originIpAddress)
    }

    /**
     * Test handling of complex user agent strings.
     */
    @Test
    fun testComplexUserAgent() {
        val userAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        val jsonString = """{"originUserAgent": "$userAgent"}"""

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals(userAgent, transactionData.originUserAgent)
    }

    /**
     * Test AdditionalDataItem with empty name.
     */
    @Test
    fun testAdditionalDataItemWithEmptyName() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "", "value": "someValue"}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNotNull(transactionData.additionalData)
        assertEquals(1, transactionData.additionalData?.size)
        assertEquals("", transactionData.additionalData?.get(0)?.name)
        assertEquals("someValue", transactionData.additionalData?.get(0)?.value)
    }

    /**
     * Test AdditionalDataItem with empty value.
     */
    @Test
    fun testAdditionalDataItemWithEmptyValue() {
        val jsonString = """
            {
                "additionalData": [
                    {"name": "someName", "value": ""}
                ]
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNotNull(transactionData.additionalData)
        assertEquals(1, transactionData.additionalData?.size)
        assertEquals("someName", transactionData.additionalData?.get(0)?.name)
        assertEquals("", transactionData.additionalData?.get(0)?.value)
    }

    /**
     * Test handling of unknown JSON fields (should be ignored).
     */
    @Test
    fun testUnknownFieldsIgnored() {
        val jsonString = """
            {
                "message": "Test",
                "unknownField1": "value1",
                "unknownField2": 123,
                "unknownField3": true
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertEquals("Test", transactionData.message)
        // Unknown fields should be ignored without causing errors
    }

    /**
     * Test malformed JSON handling.
     */
    @Test(expected = SerializationException::class)
    fun testMalformedJson() {
        val jsonString = """{"message": "Test", "invalid}"""
        json.decodeFromString<TransactionData>(jsonString)
    }

    /**
     * Test null values in JSON.
     */
    @Test
    fun testNullValuesInJson() {
        val jsonString = """
            {
                "message": null,
                "originIpAddress": null,
                "originUserAgent": null,
                "additionalData": null
            }
        """.trimIndent()

        val transactionData = json.decodeFromString<TransactionData>(jsonString)

        assertNull(transactionData.message)
        assertNull(transactionData.originIpAddress)
        assertNull(transactionData.originUserAgent)
        assertNull(transactionData.additionalData)
    }

    /**
     * Test data class equality.
     */
    @Test
    fun testDataClassEquality() {
        val data1 = TransactionData(
            message = "Test",
            originIpAddress = "192.168.1.1",
            originUserAgent = "Agent/1.0",
            additionalData = listOf(AdditionalDataItem("key", "value"))
        )

        val data2 = TransactionData(
            message = "Test",
            originIpAddress = "192.168.1.1",
            originUserAgent = "Agent/1.0",
            additionalData = listOf(AdditionalDataItem("key", "value"))
        )

        assertEquals(data1, data2)
        assertEquals(data1.hashCode(), data2.hashCode())
    }

    /**
     * Test data class copy functionality.
     */
    @Test
    fun testDataClassCopy() {
        val original = TransactionData(
            message = "Original",
            originIpAddress = "192.168.1.1",
            originUserAgent = "Agent/1.0",
            additionalData = null
        )

        val modified = original.copy(message = "Modified")

        assertEquals("Modified", modified.message)
        assertEquals(original.originIpAddress, modified.originIpAddress)
        assertEquals(original.originUserAgent, modified.originUserAgent)
        assertEquals(original.additionalData, modified.additionalData)
    }

    /**
     * Test AdditionalDataItem equality.
     */
    @Test
    fun testAdditionalDataItemEquality() {
        val item1 = AdditionalDataItem("name", "value")
        val item2 = AdditionalDataItem("name", "value")
        val item3 = AdditionalDataItem("name", "different")

        assertEquals(item1, item2)
        assertNotEquals(item1, item3)
    }
}
