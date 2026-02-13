/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HashAlgorithmTypeTest {

    @Test
    fun enumValues_shouldContainAllAlgorithms() {
        // Given
        val expectedAlgorithms = setOf(
            HashAlgorithmType.SHA1,
            HashAlgorithmType.SHA256,
            HashAlgorithmType.SHA384,
            HashAlgorithmType.SHA512
        )

        // When
        val actualAlgorithms = HashAlgorithmType.values().toSet()

        // Then
        assertEquals(expectedAlgorithms, actualAlgorithms)
        assertEquals(4, HashAlgorithmType.values().size)
    }

    @Test
    fun toString_shouldReturnHmacFormat() {
        // Then
        assertEquals("HmacSHA1", HashAlgorithmType.SHA1.toString())
        assertEquals("HmacSHA256", HashAlgorithmType.SHA256.toString())
        assertEquals("HmacSHA384", HashAlgorithmType.SHA384.toString())
        assertEquals("HmacSHA512", HashAlgorithmType.SHA512.toString())
    }

    @Test
    fun fromString_withSHA1_shouldReturnSHA1() {
        // When
        val result = HashAlgorithmType.fromString("SHA1")

        // Then
        assertEquals(HashAlgorithmType.SHA1, result)
    }

    @Test
    fun fromString_withHmacSHA1_shouldReturnSHA1() {
        // When
        val result = HashAlgorithmType.fromString("HmacSHA1")

        // Then
        assertEquals(HashAlgorithmType.SHA1, result)
    }

    @Test
    fun fromString_withRSASHA1_shouldReturnSHA1() {
        // When
        val result = HashAlgorithmType.fromString("RSASHA1")

        // Then
        assertEquals(HashAlgorithmType.SHA1, result)
    }

    @Test
    fun fromString_withSHA1WithRSA_shouldReturnSHA1() {
        // When
        val result = HashAlgorithmType.fromString("SHA1withRSA")

        // Then
        assertEquals(HashAlgorithmType.SHA1, result)
    }

    @Test
    fun fromString_withSHA256_shouldReturnSHA256() {
        // When
        val result = HashAlgorithmType.fromString("SHA256")

        // Then
        assertEquals(HashAlgorithmType.SHA256, result)
    }

    @Test
    fun fromString_withHmacSHA256_shouldReturnSHA256() {
        // When
        val result = HashAlgorithmType.fromString("HmacSHA256")

        // Then
        assertEquals(HashAlgorithmType.SHA256, result)
    }

    @Test
    fun fromString_withRSASHA256_shouldReturnSHA256() {
        // When
        val result = HashAlgorithmType.fromString("RSASHA256")

        // Then
        assertEquals(HashAlgorithmType.SHA256, result)
    }

    @Test
    fun fromString_withSHA256WithRSA_shouldReturnSHA256() {
        // When
        val result = HashAlgorithmType.fromString("SHA256withRSA")

        // Then
        assertEquals(HashAlgorithmType.SHA256, result)
    }

    @Test
    fun fromString_withSHA384_shouldReturnSHA384() {
        // When
        val result = HashAlgorithmType.fromString("SHA384")

        // Then
        assertEquals(HashAlgorithmType.SHA384, result)
    }

    @Test
    fun fromString_withHmacSHA384_shouldReturnSHA384() {
        // When
        val result = HashAlgorithmType.fromString("HmacSHA384")

        // Then
        assertEquals(HashAlgorithmType.SHA384, result)
    }

    @Test
    fun fromString_withRSASHA384_shouldReturnSHA384() {
        // When
        val result = HashAlgorithmType.fromString("RSASHA384")

        // Then
        assertEquals(HashAlgorithmType.SHA384, result)
    }

    @Test
    fun fromString_withSHA384WithRSA_shouldReturnSHA384() {
        // When
        val result = HashAlgorithmType.fromString("SHA384withRSA")

        // Then
        assertEquals(HashAlgorithmType.SHA384, result)
    }

    @Test
    fun fromString_withSHA512_shouldReturnSHA512() {
        // When
        val result = HashAlgorithmType.fromString("SHA512")

        // Then
        assertEquals(HashAlgorithmType.SHA512, result)
    }

    @Test
    fun fromString_withHmacSHA512_shouldReturnSHA512() {
        // When
        val result = HashAlgorithmType.fromString("HmacSHA512")

        // Then
        assertEquals(HashAlgorithmType.SHA512, result)
    }

    @Test
    fun fromString_withRSASHA512_shouldReturnSHA512() {
        // When
        val result = HashAlgorithmType.fromString("RSASHA512")

        // Then
        assertEquals(HashAlgorithmType.SHA512, result)
    }

    @Test
    fun fromString_withSHA512WithRSA_shouldReturnSHA512() {
        // When
        val result = HashAlgorithmType.fromString("SHA512withRSA")

        // Then
        assertEquals(HashAlgorithmType.SHA512, result)
    }

    @Test
    fun fromString_withLowercase_shouldReturnCorrectAlgorithm() {
        // Then
        assertEquals(HashAlgorithmType.SHA1, HashAlgorithmType.fromString("sha1"))
        assertEquals(HashAlgorithmType.SHA256, HashAlgorithmType.fromString("sha256"))
        assertEquals(HashAlgorithmType.SHA384, HashAlgorithmType.fromString("sha384"))
        assertEquals(HashAlgorithmType.SHA512, HashAlgorithmType.fromString("sha512"))
    }

    @Test
    fun fromString_withMixedCase_shouldReturnCorrectAlgorithm() {
        // Then
        assertEquals(HashAlgorithmType.SHA1, HashAlgorithmType.fromString("HmAcShA1"))
        assertEquals(HashAlgorithmType.SHA256, HashAlgorithmType.fromString("HmAcShA256"))
        assertEquals(HashAlgorithmType.SHA384, HashAlgorithmType.fromString("HmAcShA384"))
        assertEquals(HashAlgorithmType.SHA512, HashAlgorithmType.fromString("HmAcShA512"))
    }

    @Test(expected = HashAlgorithmException.InvalidHash::class)
    fun fromString_withInvalidAlgorithm_shouldThrowException() {
        // When
        HashAlgorithmType.fromString("INVALID")
    }

    @Test(expected = HashAlgorithmException.InvalidHash::class)
    fun fromString_withEmptyString_shouldThrowException() {
        // When
        HashAlgorithmType.fromString("")
    }

    @Test(expected = HashAlgorithmException.InvalidHash::class)
    fun fromString_withMD5_shouldThrowException() {
        // When
        HashAlgorithmType.fromString("MD5")
    }

    @Test
    fun forSigning_withSHA1_shouldReturnSHA1withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("SHA1")

        // Then
        assertEquals("SHA1withRSA", result)
    }

    @Test
    fun forSigning_withHmacSHA1_shouldReturnSHA1withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("HmacSHA1")

        // Then
        assertEquals("SHA1withRSA", result)
    }

    @Test
    fun forSigning_withRSASHA1_shouldReturnSHA1withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("RSASHA1")

        // Then
        assertEquals("SHA1withRSA", result)
    }

    @Test
    fun forSigning_withSHA1WithRSA_shouldReturnSHA1withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("SHA1withRSA")

        // Then
        assertEquals("SHA1withRSA", result)
    }

    @Test
    fun forSigning_withSHA256_shouldReturnSHA256withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("SHA256")

        // Then
        assertEquals("SHA256withRSA", result)
    }

    @Test
    fun forSigning_withHmacSHA256_shouldReturnSHA256withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("HmacSHA256")

        // Then
        assertEquals("SHA256withRSA", result)
    }

    @Test
    fun forSigning_withRSASHA256_shouldReturnSHA256withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("RSASHA256")

        // Then
        assertEquals("SHA256withRSA", result)
    }

    @Test
    fun forSigning_withSHA256WithRSA_shouldReturnSHA256withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("SHA256withRSA")

        // Then
        assertEquals("SHA256withRSA", result)
    }

    @Test
    fun forSigning_withSHA384_shouldReturnSHA384withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("SHA384")

        // Then
        assertEquals("SHA384withRSA", result)
    }

    @Test
    fun forSigning_withHmacSHA384_shouldReturnSHA384withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("HmacSHA384")

        // Then
        assertEquals("SHA384withRSA", result)
    }

    @Test
    fun forSigning_withRSASHA384_shouldReturnSHA384withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("RSASHA384")

        // Then
        assertEquals("SHA384withRSA", result)
    }

    @Test
    fun forSigning_withSHA384WithRSA_shouldReturnSHA384withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("SHA384withRSA")

        // Then
        assertEquals("SHA384withRSA", result)
    }

    @Test
    fun forSigning_withSHA512_shouldReturnSHA512withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("SHA512")

        // Then
        assertEquals("SHA512withRSA", result)
    }

    @Test
    fun forSigning_withHmacSHA512_shouldReturnSHA512withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("HmacSHA512")

        // Then
        assertEquals("SHA512withRSA", result)
    }

    @Test
    fun forSigning_withRSASHA512_shouldReturnSHA512withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("RSASHA512")

        // Then
        assertEquals("SHA512withRSA", result)
    }

    @Test
    fun forSigning_withSHA512WithRSA_shouldReturnSHA512withRSA() {
        // When
        val result = HashAlgorithmType.forSigning("SHA512withRSA")

        // Then
        assertEquals("SHA512withRSA", result)
    }

    @Test
    fun forSigning_withLowercase_shouldReturnCorrectFormat() {
        // Then
        assertEquals("SHA1withRSA", HashAlgorithmType.forSigning("sha1"))
        assertEquals("SHA256withRSA", HashAlgorithmType.forSigning("sha256"))
        assertEquals("SHA384withRSA", HashAlgorithmType.forSigning("sha384"))
        assertEquals("SHA512withRSA", HashAlgorithmType.forSigning("sha512"))
    }

    @Test(expected = HashAlgorithmException.InvalidHash::class)
    fun forSigning_withInvalidAlgorithm_shouldThrowException() {
        // When
        HashAlgorithmType.forSigning("INVALID")
    }

    @Test(expected = HashAlgorithmException.InvalidHash::class)
    fun forSigning_withEmptyString_shouldThrowException() {
        // When
        HashAlgorithmType.forSigning("")
    }

    @Test
    fun toIsvFormat_withSHA1_shouldReturnRSASHA1() {
        // When
        val result = HashAlgorithmType.toIsvFormat(HashAlgorithmType.SHA1)

        // Then
        assertEquals("RSASHA1", result)
    }

    @Test
    fun toIsvFormat_withSHA256_shouldReturnRSASHA256() {
        // When
        val result = HashAlgorithmType.toIsvFormat(HashAlgorithmType.SHA256)

        // Then
        assertEquals("RSASHA256", result)
    }

    @Test
    fun toIsvFormat_withSHA384_shouldReturnRSASHA384() {
        // When
        val result = HashAlgorithmType.toIsvFormat(HashAlgorithmType.SHA384)

        // Then
        assertEquals("RSASHA384", result)
    }

    @Test
    fun toIsvFormat_withSHA512_shouldReturnRSASHA512() {
        // When
        val result = HashAlgorithmType.toIsvFormat(HashAlgorithmType.SHA512)

        // Then
        assertEquals("RSASHA512", result)
    }

    @Test
    fun toIsvFormat_allAlgorithms_shouldReturnCorrectFormat() {
        // Given
        val expectedMappings = mapOf(
            HashAlgorithmType.SHA1 to "RSASHA1",
            HashAlgorithmType.SHA256 to "RSASHA256",
            HashAlgorithmType.SHA384 to "RSASHA384",
            HashAlgorithmType.SHA512 to "RSASHA512"
        )

        // When/Then
        for ((algorithm, expected) in expectedMappings) {
            val result = HashAlgorithmType.toIsvFormat(algorithm)
            assertEquals(expected, result)
        }
    }

    @Test
    fun ordinal_shouldReturnCorrectOrder() {
        // Then
        assertEquals(0, HashAlgorithmType.SHA1.ordinal)
        assertEquals(1, HashAlgorithmType.SHA256.ordinal)
        assertEquals(2, HashAlgorithmType.SHA384.ordinal)
        assertEquals(3, HashAlgorithmType.SHA512.ordinal)
    }

    @Test
    fun name_shouldReturnEnumName() {
        // Then
        assertEquals("SHA1", HashAlgorithmType.SHA1.name)
        assertEquals("SHA256", HashAlgorithmType.SHA256.name)
        assertEquals("SHA384", HashAlgorithmType.SHA384.name)
        assertEquals("SHA512", HashAlgorithmType.SHA512.name)
    }

    @Test
    fun valueOf_withValidName_shouldReturnEnumValue() {
        // Then
        assertEquals(HashAlgorithmType.SHA1, HashAlgorithmType.valueOf("SHA1"))
        assertEquals(HashAlgorithmType.SHA256, HashAlgorithmType.valueOf("SHA256"))
        assertEquals(HashAlgorithmType.SHA384, HashAlgorithmType.valueOf("SHA384"))
        assertEquals(HashAlgorithmType.SHA512, HashAlgorithmType.valueOf("SHA512"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun valueOf_withInvalidName_shouldThrowException() {
        // When
        HashAlgorithmType.valueOf("INVALID")
    }

    @Test
    fun compareTo_shouldCompareByOrdinal() {
        // Then
        assert(HashAlgorithmType.SHA1 < HashAlgorithmType.SHA256)
        assert(HashAlgorithmType.SHA256 < HashAlgorithmType.SHA384)
        assert(HashAlgorithmType.SHA384 < HashAlgorithmType.SHA512)
    }

    @Test
    fun fromString_roundTrip_shouldPreserveValue() {
        // Given
        val algorithms = HashAlgorithmType.values()

        // When/Then
        for (algorithm in algorithms) {
            val result = HashAlgorithmType.fromString(algorithm.name)
            assertEquals(algorithm, result)
        }
    }

    @Test
    fun fromString_allVariations_shouldReturnCorrectAlgorithm() {
        // Test all SHA1 variations
        val sha1Variations = listOf("SHA1", "HMACSHA1", "RSASHA1", "SHA1WITHRSA")
        for (variation in sha1Variations) {
            assertEquals(HashAlgorithmType.SHA1, HashAlgorithmType.fromString(variation))
        }

        // Test all SHA256 variations
        val sha256Variations = listOf("SHA256", "HMACSHA256", "RSASHA256", "SHA256WITHRSA")
        for (variation in sha256Variations) {
            assertEquals(HashAlgorithmType.SHA256, HashAlgorithmType.fromString(variation))
        }

        // Test all SHA384 variations
        val sha384Variations = listOf("SHA384", "HMACSHA384", "RSASHA384", "SHA384WITHRSA")
        for (variation in sha384Variations) {
            assertEquals(HashAlgorithmType.SHA384, HashAlgorithmType.fromString(variation))
        }

        // Test all SHA512 variations
        val sha512Variations = listOf("SHA512", "HMACSHA512", "RSASHA512", "SHA512WITHRSA")
        for (variation in sha512Variations) {
            assertEquals(HashAlgorithmType.SHA512, HashAlgorithmType.fromString(variation))
        }
    }
}
