/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.onprem

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TotpConfigurationTest {

    private val testPeriod = "30"
    private val testSecretKeyUrl = "https://example.com/secret"
    private val testSecretKey = "JBSWY3DPEHPK3PXP"
    private val testDigits = "6"
    private val testUsername = "test@example.com"
    private val testAlgorithm = "SHA256"

    @Test
    fun constructor_withAllFields_shouldCreateInstance() {
        // When
        val config = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // Then
        assertEquals(testPeriod, config.period)
        assertEquals(testSecretKeyUrl, config.secretKeyUrl)
        assertEquals(testSecretKey, config.secretKey)
        assertEquals(testDigits, config.digits)
        assertEquals(testUsername, config.username)
        assertEquals(testAlgorithm, config.algorithm)
    }

    @Test
    fun constructor_withDifferentPeriod_shouldSetPeriod() {
        // Given
        val differentPeriod = "60"

        // When
        val config = TotpConfiguration(
            period = differentPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // Then
        assertEquals(differentPeriod, config.period)
    }

    @Test
    fun constructor_withDifferentDigits_shouldSetDigits() {
        // Given
        val differentDigits = "8"

        // When
        val config = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = differentDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // Then
        assertEquals(differentDigits, config.digits)
    }

    @Test
    fun constructor_withDifferentAlgorithm_shouldSetAlgorithm() {
        // Given
        val differentAlgorithm = "SHA512"

        // When
        val config = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = differentAlgorithm
        )

        // Then
        assertEquals(differentAlgorithm, config.algorithm)
    }

    @Test
    fun serialization_shouldSerializeAndDeserialize() {
        // Given
        val config = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(config)
        val deserialized = json.decodeFromString<TotpConfiguration>(serialized)

        // Then
        assertEquals(config.period, deserialized.period)
        assertEquals(config.secretKeyUrl, deserialized.secretKeyUrl)
        assertEquals(config.secretKey, deserialized.secretKey)
        assertEquals(config.digits, deserialized.digits)
        assertEquals(config.username, deserialized.username)
        assertEquals(config.algorithm, deserialized.algorithm)
    }

    @Test
    fun deserialization_fromJsonString_shouldCreateInstance() {
        // Given
        val jsonString = """
            {
                "period": "30",
                "secretKeyUrl": "https://example.com/secret",
                "secretKey": "JBSWY3DPEHPK3PXP",
                "digits": "6",
                "username": "test@example.com",
                "algorithm": "SHA256"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val config = json.decodeFromString<TotpConfiguration>(jsonString)

        // Then
        assertEquals(testPeriod, config.period)
        assertEquals(testSecretKeyUrl, config.secretKeyUrl)
        assertEquals(testSecretKey, config.secretKey)
        assertEquals(testDigits, config.digits)
        assertEquals(testUsername, config.username)
        assertEquals(testAlgorithm, config.algorithm)
    }

    @Test
    fun deserialization_withExtraFields_shouldIgnoreExtraFields() {
        // Given
        val jsonString = """
            {
                "period": "30",
                "secretKeyUrl": "https://example.com/secret",
                "secretKey": "JBSWY3DPEHPK3PXP",
                "digits": "6",
                "username": "test@example.com",
                "algorithm": "SHA256",
                "extraField": "extraValue"
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val config = json.decodeFromString<TotpConfiguration>(jsonString)

        // Then
        assertEquals(testPeriod, config.period)
        assertEquals(testSecretKeyUrl, config.secretKeyUrl)
        assertEquals(testSecretKey, config.secretKey)
        assertEquals(testDigits, config.digits)
        assertEquals(testUsername, config.username)
        assertEquals(testAlgorithm, config.algorithm)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.period, copy.period)
        assertEquals(original.secretKeyUrl, copy.secretKeyUrl)
        assertEquals(original.secretKey, copy.secretKey)
        assertEquals(original.digits, copy.digits)
        assertEquals(original.username, copy.username)
        assertEquals(original.algorithm, copy.algorithm)
    }

    @Test
    fun copy_withModifiedPeriod_shouldUpdateOnlyPeriod() {
        // Given
        val original = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // When
        val modified = original.copy(period = "60")

        // Then
        assertEquals("60", modified.period)
        assertEquals(original.secretKeyUrl, modified.secretKeyUrl)
        assertEquals(original.secretKey, modified.secretKey)
        assertEquals(original.digits, modified.digits)
        assertEquals(original.username, modified.username)
        assertEquals(original.algorithm, modified.algorithm)
    }

    @Test
    fun copy_withModifiedSecretKey_shouldUpdateOnlySecretKey() {
        // Given
        val original = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // When
        val modified = original.copy(secretKey = "NEWSECRET123")

        // Then
        assertEquals(original.period, modified.period)
        assertEquals("NEWSECRET123", modified.secretKey)
        assertEquals(original.digits, modified.digits)
    }

    @Test
    fun copy_withModifiedDigits_shouldUpdateOnlyDigits() {
        // Given
        val original = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // When
        val modified = original.copy(digits = "8")

        // Then
        assertEquals("8", modified.digits)
        assertEquals(original.period, modified.period)
        assertEquals(original.secretKey, modified.secretKey)
    }

    @Test
    fun copy_withModifiedUsername_shouldUpdateOnlyUsername() {
        // Given
        val original = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // When
        val modified = original.copy(username = "new@example.com")

        // Then
        assertEquals("new@example.com", modified.username)
        assertEquals(original.period, modified.period)
        assertEquals(original.algorithm, modified.algorithm)
    }

    @Test
    fun copy_withModifiedAlgorithm_shouldUpdateOnlyAlgorithm() {
        // Given
        val original = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // When
        val modified = original.copy(algorithm = "SHA512")

        // Then
        assertEquals("SHA512", modified.algorithm)
        assertEquals(original.period, modified.period)
        assertEquals(original.digits, modified.digits)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val config1 = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )
        val config2 = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // Then
        assertEquals(config1, config2)
    }

    @Test
    fun equals_withDifferentPeriod_shouldReturnFalse() {
        // Given
        val config1 = TotpConfiguration(
            period = "30",
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )
        val config2 = TotpConfiguration(
            period = "60",
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // Then
        assertNotEquals(config1, config2)
    }

    @Test
    fun equals_withDifferentSecretKey_shouldReturnFalse() {
        // Given
        val config1 = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = "SECRET1",
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )
        val config2 = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = "SECRET2",
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // Then
        assertNotEquals(config1, config2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val config1 = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )
        val config2 = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // Then
        assertEquals(config1.hashCode(), config2.hashCode())
    }

    @Test
    fun toString_shouldContainAllProperties() {
        // Given
        val config = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // When
        val result = config.toString()

        // Then
        assert(result.contains("TotpConfiguration"))
        assert(result.contains(testPeriod))
        assert(result.contains(testDigits))
        assert(result.contains(testUsername))
        assert(result.contains(testAlgorithm))
    }

    @Test
    fun allProperties_shouldNotBeNull() {
        // Given
        val config = TotpConfiguration(
            period = testPeriod,
            secretKeyUrl = testSecretKeyUrl,
            secretKey = testSecretKey,
            digits = testDigits,
            username = testUsername,
            algorithm = testAlgorithm
        )

        // Then
        assertNotNull(config.period)
        assertNotNull(config.secretKeyUrl)
        assertNotNull(config.secretKey)
        assertNotNull(config.digits)
        assertNotNull(config.username)
        assertNotNull(config.algorithm)
    }

    @Test
    fun constructor_withCommonPeriodValues_shouldSetCorrectly() {
        // Test common period values
        val config15 = TotpConfiguration("15", testSecretKeyUrl, testSecretKey, testDigits, testUsername, testAlgorithm)
        val config30 = TotpConfiguration("30", testSecretKeyUrl, testSecretKey, testDigits, testUsername, testAlgorithm)
        val config60 = TotpConfiguration("60", testSecretKeyUrl, testSecretKey, testDigits, testUsername, testAlgorithm)

        // Then
        assertEquals("15", config15.period)
        assertEquals("30", config30.period)
        assertEquals("60", config60.period)
    }

    @Test
    fun constructor_withCommonDigitValues_shouldSetCorrectly() {
        // Test common digit values
        val config6 = TotpConfiguration(testPeriod, testSecretKeyUrl, testSecretKey, "6", testUsername, testAlgorithm)
        val config8 = TotpConfiguration(testPeriod, testSecretKeyUrl, testSecretKey, "8", testUsername, testAlgorithm)

        // Then
        assertEquals("6", config6.digits)
        assertEquals("8", config8.digits)
    }

    @Test
    fun constructor_withCommonAlgorithms_shouldSetCorrectly() {
        // Test common algorithms
        val configSHA1 = TotpConfiguration(testPeriod, testSecretKeyUrl, testSecretKey, testDigits, testUsername, "SHA1")
        val configSHA256 = TotpConfiguration(testPeriod, testSecretKeyUrl, testSecretKey, testDigits, testUsername, "SHA256")
        val configSHA512 = TotpConfiguration(testPeriod, testSecretKeyUrl, testSecretKey, testDigits, testUsername, "SHA512")

        // Then
        assertEquals("SHA1", configSHA1.algorithm)
        assertEquals("SHA256", configSHA256.algorithm)
        assertEquals("SHA512", configSHA512.algorithm)
    }
}


