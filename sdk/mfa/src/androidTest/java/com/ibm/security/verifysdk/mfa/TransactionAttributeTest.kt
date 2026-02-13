/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TransactionAttributeTest {

    @Test
    fun enumValues_shouldContainAllAttributes() {
        // Given
        val expectedAttributes = setOf(
            TransactionAttribute.IPAddress,
            TransactionAttribute.Location,
            TransactionAttribute.Image,
            TransactionAttribute.UserAgent,
            TransactionAttribute.Type,
            TransactionAttribute.Custom
        )

        // When
        val actualAttributes = TransactionAttribute.values().toSet()

        // Then
        assertEquals(expectedAttributes, actualAttributes)
        assertEquals(6, TransactionAttribute.values().size)
    }

    @Test
    fun ipAddress_rawValueShouldBeIpAddress() {
        // When
        val rawValue = TransactionAttribute.IPAddress.rawValue

        // Then
        assertEquals("ipAddress", rawValue)
    }

    @Test
    fun location_rawValueShouldBeLocation() {
        // When
        val rawValue = TransactionAttribute.Location.rawValue

        // Then
        assertEquals("location", rawValue)
    }

    @Test
    fun image_rawValueShouldBeImage() {
        // When
        val rawValue = TransactionAttribute.Image.rawValue

        // Then
        assertEquals("image", rawValue)
    }

    @Test
    fun userAgent_rawValueShouldBeUserAgent() {
        // When
        val rawValue = TransactionAttribute.UserAgent.rawValue

        // Then
        assertEquals("userAgent", rawValue)
    }

    @Test
    fun type_rawValueShouldBeType() {
        // When
        val rawValue = TransactionAttribute.Type.rawValue

        // Then
        assertEquals("type", rawValue)
    }

    @Test
    fun custom_rawValueShouldBeCustom() {
        // When
        val rawValue = TransactionAttribute.Custom.rawValue

        // Then
        assertEquals("custom", rawValue)
    }

    @Test
    fun allAttributes_shouldHaveUniqueRawValues() {
        // Given
        val attributes = TransactionAttribute.values()

        // When
        val rawValues = attributes.map { it.rawValue }.toSet()

        // Then
        assertEquals(attributes.size, rawValues.size)
    }

    @Test
    fun name_shouldReturnEnumName() {
        // Then
        assertEquals("IPAddress", TransactionAttribute.IPAddress.name)
        assertEquals("Location", TransactionAttribute.Location.name)
        assertEquals("Image", TransactionAttribute.Image.name)
        assertEquals("UserAgent", TransactionAttribute.UserAgent.name)
        assertEquals("Type", TransactionAttribute.Type.name)
        assertEquals("Custom", TransactionAttribute.Custom.name)
    }

    @Test
    fun valueOf_withValidName_shouldReturnEnumValue() {
        // Then
        assertEquals(TransactionAttribute.IPAddress, TransactionAttribute.valueOf("IPAddress"))
        assertEquals(TransactionAttribute.Location, TransactionAttribute.valueOf("Location"))
        assertEquals(TransactionAttribute.Image, TransactionAttribute.valueOf("Image"))
        assertEquals(TransactionAttribute.UserAgent, TransactionAttribute.valueOf("UserAgent"))
        assertEquals(TransactionAttribute.Type, TransactionAttribute.valueOf("Type"))
        assertEquals(TransactionAttribute.Custom, TransactionAttribute.valueOf("Custom"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun valueOf_withInvalidName_shouldThrowException() {
        // When
        TransactionAttribute.valueOf("INVALID")
    }

    @Test
    fun ordinal_shouldReturnCorrectOrder() {
        // Then
        assertEquals(0, TransactionAttribute.IPAddress.ordinal)
        assertEquals(1, TransactionAttribute.Location.ordinal)
        assertEquals(2, TransactionAttribute.Image.ordinal)
        assertEquals(3, TransactionAttribute.UserAgent.ordinal)
        assertEquals(4, TransactionAttribute.Type.ordinal)
        assertEquals(5, TransactionAttribute.Custom.ordinal)
    }

    @Test
    fun compareTo_shouldCompareByOrdinal() {
        // Then
        assert(TransactionAttribute.IPAddress < TransactionAttribute.Location)
        assert(TransactionAttribute.Location < TransactionAttribute.Image)
        assert(TransactionAttribute.Image < TransactionAttribute.UserAgent)
        assert(TransactionAttribute.UserAgent < TransactionAttribute.Type)
        assert(TransactionAttribute.Type < TransactionAttribute.Custom)
    }

    @Test
    fun toString_shouldReturnEnumName() {
        // Then
        assertEquals("IPAddress", TransactionAttribute.IPAddress.toString())
        assertEquals("Location", TransactionAttribute.Location.toString())
        assertEquals("Image", TransactionAttribute.Image.toString())
        assertEquals("UserAgent", TransactionAttribute.UserAgent.toString())
        assertEquals("Type", TransactionAttribute.Type.toString())
        assertEquals("Custom", TransactionAttribute.Custom.toString())
    }

    @Test
    fun ipAddress_shouldHaveCorrectProperties() {
        // Given
        val attribute = TransactionAttribute.IPAddress

        // Then
        assertEquals("ipAddress", attribute.rawValue)
        assertEquals("IPAddress", attribute.name)
        assertEquals(0, attribute.ordinal)
    }

    @Test
    fun location_shouldHaveCorrectProperties() {
        // Given
        val attribute = TransactionAttribute.Location

        // Then
        assertEquals("location", attribute.rawValue)
        assertEquals("Location", attribute.name)
        assertEquals(1, attribute.ordinal)
    }

    @Test
    fun image_shouldHaveCorrectProperties() {
        // Given
        val attribute = TransactionAttribute.Image

        // Then
        assertEquals("image", attribute.rawValue)
        assertEquals("Image", attribute.name)
        assertEquals(2, attribute.ordinal)
    }

    @Test
    fun userAgent_shouldHaveCorrectProperties() {
        // Given
        val attribute = TransactionAttribute.UserAgent

        // Then
        assertEquals("userAgent", attribute.rawValue)
        assertEquals("UserAgent", attribute.name)
        assertEquals(3, attribute.ordinal)
    }

    @Test
    fun type_shouldHaveCorrectProperties() {
        // Given
        val attribute = TransactionAttribute.Type

        // Then
        assertEquals("type", attribute.rawValue)
        assertEquals("Type", attribute.name)
        assertEquals(4, attribute.ordinal)
    }

    @Test
    fun custom_shouldHaveCorrectProperties() {
        // Given
        val attribute = TransactionAttribute.Custom

        // Then
        assertEquals("custom", attribute.rawValue)
        assertEquals("Custom", attribute.name)
        assertEquals(5, attribute.ordinal)
    }

    @Test
    fun allAttributes_shouldHaveDistinctNames() {
        // Given
        val attributes = TransactionAttribute.values()

        // When
        val names = attributes.map { it.name }.toSet()

        // Then
        assertEquals(attributes.size, names.size)
    }

    @Test
    fun allAttributes_shouldHaveDistinctOrdinals() {
        // Given
        val attributes = TransactionAttribute.values()

        // When
        val ordinals = attributes.map { it.ordinal }.toSet()

        // Then
        assertEquals(attributes.size, ordinals.size)
    }

    @Test
    fun rawValueProperty_shouldBeAccessible() {
        // When/Then
        assertEquals("ipAddress", TransactionAttribute.IPAddress.rawValue)
        assertEquals("location", TransactionAttribute.Location.rawValue)
        assertEquals("image", TransactionAttribute.Image.rawValue)
        assertEquals("userAgent", TransactionAttribute.UserAgent.rawValue)
        assertEquals("type", TransactionAttribute.Type.rawValue)
        assertEquals("custom", TransactionAttribute.Custom.rawValue)
    }

    @Test
    fun whenExpression_shouldBeExhaustive() {
        // Given
        val attributes = TransactionAttribute.values()

        // When/Then - Verify all attributes can be handled
        for (attribute in attributes) {
            val result = when (attribute) {
                TransactionAttribute.IPAddress -> "ip"
                TransactionAttribute.Location -> "loc"
                TransactionAttribute.Image -> "img"
                TransactionAttribute.UserAgent -> "ua"
                TransactionAttribute.Type -> "type"
                TransactionAttribute.Custom -> "custom"
            }
            assert(result.isNotEmpty())
        }
    }

    @Test
    fun equality_shouldWorkCorrectly() {
        // Given
        val attribute1 = TransactionAttribute.IPAddress
        val attribute2 = TransactionAttribute.IPAddress
        val attribute3 = TransactionAttribute.Location

        // Then
        assertEquals(attribute1, attribute2)
        assert(attribute1 != attribute3)
    }

    @Test
    fun hashCode_shouldBeConsistent() {
        // Given
        val attribute1 = TransactionAttribute.IPAddress
        val attribute2 = TransactionAttribute.IPAddress

        // Then
        assertEquals(attribute1.hashCode(), attribute2.hashCode())
    }

    @Test
    fun rawValues_shouldFollowCamelCaseConvention() {
        // Then - Most follow camelCase except lowercase ones
        assertEquals("ipAddress", TransactionAttribute.IPAddress.rawValue)
        assertEquals("location", TransactionAttribute.Location.rawValue)
        assertEquals("image", TransactionAttribute.Image.rawValue)
        assertEquals("userAgent", TransactionAttribute.UserAgent.rawValue)
        assertEquals("type", TransactionAttribute.Type.rawValue)
        assertEquals("custom", TransactionAttribute.Custom.rawValue)
    }
}

