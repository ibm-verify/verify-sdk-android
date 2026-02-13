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
    fun fromString_withTOTP_shouldReturnTOTP() {
        // When
        val result = EnrollableType.fromString("TOTP")

        // Then
        assertEquals(EnrollableType.TOTP, result)
    }

    @Test
    fun fromString_withTOTPLowercase_shouldReturnTOTP() {
        // When
        val result = EnrollableType.fromString("totp")

        // Then
        assertEquals(EnrollableType.TOTP, result)
    }

    @Test
    fun fromString_withTOTPMixedCase_shouldReturnTOTP() {
        // When
        val result = EnrollableType.fromString("ToTp")

        // Then
        assertEquals(EnrollableType.TOTP, result)
    }

    @Test
    fun fromString_withHOTP_shouldReturnHOTP() {
        // When
        val result = EnrollableType.fromString("HOTP")

        // Then
        assertEquals(EnrollableType.HOTP, result)
    }

    @Test
    fun fromString_withHOTPLowercase_shouldReturnHOTP() {
        // When
        val result = EnrollableType.fromString("hotp")

        // Then
        assertEquals(EnrollableType.HOTP, result)
    }

    @Test
    fun fromString_withFACE_shouldReturnFACE() {
        // When
        val result = EnrollableType.fromString("FACE")

        // Then
        assertEquals(EnrollableType.FACE, result)
    }

    @Test
    fun fromString_withFACELowercase_shouldReturnFACE() {
        // When
        val result = EnrollableType.fromString("face")

        // Then
        assertEquals(EnrollableType.FACE, result)
    }

    @Test
    fun fromString_withFINGERPRINT_shouldReturnFINGERPRINT() {
        // When
        val result = EnrollableType.fromString("FINGERPRINT")

        // Then
        assertEquals(EnrollableType.FINGERPRINT, result)
    }

    @Test
    fun fromString_withFINGERPRINTLowercase_shouldReturnFINGERPRINT() {
        // When
        val result = EnrollableType.fromString("fingerprint")

        // Then
        assertEquals(EnrollableType.FINGERPRINT, result)
    }

    @Test
    fun fromString_withUSER_PRESENCE_shouldReturnUSER_PRESENCE() {
        // When
        val result = EnrollableType.fromString("USER_PRESENCE")

        // Then
        assertEquals(EnrollableType.USER_PRESENCE, result)
    }

    @Test
    fun fromString_withUSER_PRESENCELowercase_shouldReturnUSER_PRESENCE() {
        // When
        val result = EnrollableType.fromString("user_presence")

        // Then
        assertEquals(EnrollableType.USER_PRESENCE, result)
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
    fun forIsvaEnrollment_withTOTP_shouldReturnLowercase() {
        // When
        val result = EnrollableType.forIsvaEnrollment(EnrollableType.TOTP)

        // Then
        assertEquals("totp", result)
    }

    @Test
    fun forIsvaEnrollment_withHOTP_shouldReturnLowercase() {
        // When
        val result = EnrollableType.forIsvaEnrollment(EnrollableType.HOTP)

        // Then
        assertEquals("hotp", result)
    }

    @Test
    fun forIsvaEnrollment_withFACE_shouldReturnLowercase() {
        // When
        val result = EnrollableType.forIsvaEnrollment(EnrollableType.FACE)

        // Then
        assertEquals("face", result)
    }

    @Test
    fun forIsvaEnrollment_withFINGERPRINT_shouldReturnLowercase() {
        // When
        val result = EnrollableType.forIsvaEnrollment(EnrollableType.FINGERPRINT)

        // Then
        assertEquals("fingerprint", result)
    }

    @Test
    fun forIsvaEnrollment_withUSER_PRESENCE_shouldReturnUserPresence() {
        // When
        val result = EnrollableType.forIsvaEnrollment(EnrollableType.USER_PRESENCE)

        // Then
        assertEquals("userPresence", result)
    }

    @Test
    fun forIsvaEnrollment_withNull_shouldReturnEmptyString() {
        // When
        val result = EnrollableType.forIsvaEnrollment(null)

        // Then
        assertEquals("", result)
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
    fun toString_shouldReturnEnumName() {
        // Then
        assertEquals("TOTP", EnrollableType.TOTP.toString())
        assertEquals("HOTP", EnrollableType.HOTP.toString())
        assertEquals("FACE", EnrollableType.FACE.toString())
        assertEquals("FINGERPRINT", EnrollableType.FINGERPRINT.toString())
        assertEquals("USER_PRESENCE", EnrollableType.USER_PRESENCE.toString())
    }

    @Test
    fun fromString_roundTrip_shouldPreserveValue() {
        // Given
        val types = EnrollableType.values()

        // When/Then
        for (type in types) {
            val result = EnrollableType.fromString(type.name)
            assertEquals(type, result)
        }
    }

    @Test
    fun forIsvaEnrollment_allTypes_shouldReturnValidStrings() {
        // Given
        val expectedMappings = mapOf(
            EnrollableType.TOTP to "totp",
            EnrollableType.HOTP to "hotp",
            EnrollableType.FACE to "face",
            EnrollableType.FINGERPRINT to "fingerprint",
            EnrollableType.USER_PRESENCE to "userPresence"
        )

        // When/Then
        for ((type, expected) in expectedMappings) {
            val result = EnrollableType.forIsvaEnrollment(type)
            assertEquals(expected, result)
        }
    }
}
