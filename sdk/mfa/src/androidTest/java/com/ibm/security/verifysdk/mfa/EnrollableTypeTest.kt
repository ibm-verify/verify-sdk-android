/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EnrollableTypeTest {

    @Test
    fun enumValues_shouldContainAllTypes() {
        // Given
        val expectedTypes = setOf(
            EnrollableType.TOTP,
            EnrollableType.HOTP,
            EnrollableType.FACE,
            EnrollableType.FINGERPRINT,
            EnrollableType.USER_PRESENCE
        )

        // When
        val actualTypes = EnrollableType.values().toSet()

        // Then
        assertEquals(expectedTypes, actualTypes)
        assertEquals(5, EnrollableType.values().size)
    }

    @Test
    fun fromString_withTOTPLowercase_shouldReturnTOTP() {
        // When
        val result = EnrollableType.fromString("totp")

        // Then
        assertEquals(EnrollableType.TOTP, result)
    }

    @Test
    fun fromString_withTOTPUppercase_shouldReturnNull() {
        // When
        val result = EnrollableType.fromString("TOTP")

        // Then
        assertNull(result)
    }

    @Test
    fun fromString_withHOTPLowercase_shouldReturnHOTP() {
        // When
        val result = EnrollableType.fromString("hotp")

        // Then
        assertEquals(EnrollableType.HOTP, result)
    }

    @Test
    fun fromString_withFACELowercase_shouldReturnFACE() {
        // When
        val result = EnrollableType.fromString("face")

        // Then
        assertEquals(EnrollableType.FACE, result)
    }

    @Test
    fun fromString_withFINGERPRINTLowercase_shouldReturnFINGERPRINT() {
        // When
        val result = EnrollableType.fromString("fingerprint")

        // Then
        assertEquals(EnrollableType.FINGERPRINT, result)
    }

    @Test
    fun fromString_withUserPresenceCamelCase_shouldReturnUSER_PRESENCE() {
        // When
        val result = EnrollableType.fromString("userPresence")

        // Then
        assertEquals(EnrollableType.USER_PRESENCE, result)
    }

    @Test
    fun fromString_withUserPresenceUppercase_shouldReturnNull() {
        // When
        val result = EnrollableType.fromString("USER_PRESENCE")

        // Then
        assertNull(result)
    }

    @Test
    fun fromString_withInvalidString_shouldReturnNull() {
        // When
        val result = EnrollableType.fromString("INVALID_TYPE")

        // Then
        assertNull(result)
    }

    @Test
    fun fromString_withEmptyString_shouldReturnNull() {
        // When
        val result = EnrollableType.fromString("")

        // Then
        assertNull(result)
    }

    @Test
    fun fromString_withRandomString_shouldReturnNull() {
        // When
        val result = EnrollableType.fromString("RandomString123")

        // Then
        assertNull(result)
    }


    @Test
    fun name_shouldReturnEnumName() {
        // Then
        assertEquals("TOTP", EnrollableType.TOTP.name)
        assertEquals("HOTP", EnrollableType.HOTP.name)
        assertEquals("FACE", EnrollableType.FACE.name)
        assertEquals("FINGERPRINT", EnrollableType.FINGERPRINT.name)
        assertEquals("USER_PRESENCE", EnrollableType.USER_PRESENCE.name)
    }

    @Test
    fun valueOf_withValidName_shouldReturnEnumValue() {
        // Then
        assertEquals(EnrollableType.TOTP, EnrollableType.valueOf("TOTP"))
        assertEquals(EnrollableType.HOTP, EnrollableType.valueOf("HOTP"))
        assertEquals(EnrollableType.FACE, EnrollableType.valueOf("FACE"))
        assertEquals(EnrollableType.FINGERPRINT, EnrollableType.valueOf("FINGERPRINT"))
        assertEquals(EnrollableType.USER_PRESENCE, EnrollableType.valueOf("USER_PRESENCE"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun valueOf_withInvalidName_shouldThrowException() {
        // When
        EnrollableType.valueOf("INVALID")
    }

    @Test
    fun ordinal_shouldReturnCorrectOrder() {
        // Then
        assertEquals(0, EnrollableType.TOTP.ordinal)
        assertEquals(1, EnrollableType.HOTP.ordinal)
        assertEquals(2, EnrollableType.FACE.ordinal)
        assertEquals(3, EnrollableType.FINGERPRINT.ordinal)
        assertEquals(4, EnrollableType.USER_PRESENCE.ordinal)
    }

    @Test
    fun compareTo_shouldCompareByOrdinal() {
        // Then
        assert(EnrollableType.TOTP < EnrollableType.HOTP)
        assert(EnrollableType.HOTP < EnrollableType.FACE)
        assert(EnrollableType.FACE < EnrollableType.FINGERPRINT)
        assert(EnrollableType.FINGERPRINT < EnrollableType.USER_PRESENCE)
    }

    @Test
    fun toString_shouldReturnCorrectFormat() {
        // Then - matches v2 SubType.toString() format
        assertEquals("totp", EnrollableType.TOTP.toString())
        assertEquals("hotp", EnrollableType.HOTP.toString())
        assertEquals("face", EnrollableType.FACE.toString())
        assertEquals("fingerprint", EnrollableType.FINGERPRINT.toString())
        assertEquals("userPresence", EnrollableType.USER_PRESENCE.toString())
    }

    @Test
    fun fromString_toString_roundTrip_shouldPreserveValue() {
        // Given
        val types = EnrollableType.values()

        // When/Then - toString() returns the format that fromString() expects
        for (type in types) {
            val stringValue = type.toString()
            val result = EnrollableType.fromString(stringValue)
            assertEquals(type, result)
        }
    }

    @Test
    fun toString_allTypes_shouldMatchV2Format() {
        // Given - Expected format matches v2 SubType.toString()
        val expectedMappings = mapOf(
            EnrollableType.TOTP to "totp",
            EnrollableType.HOTP to "hotp",
            EnrollableType.FACE to "face",
            EnrollableType.FINGERPRINT to "fingerprint",
            EnrollableType.USER_PRESENCE to "userPresence"
        )

        // When/Then
        for ((type, expected) in expectedMappings) {
            val result = type.toString()
            assertEquals(expected, result)
        }
    }
}
