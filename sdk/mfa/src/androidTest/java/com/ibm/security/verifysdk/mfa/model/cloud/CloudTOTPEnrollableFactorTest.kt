/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.cloud

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.mfa.EnrollableType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

@RunWith(AndroidJUnit4::class)
class CloudTOTPEnrollableFactorTest {

    private val testUri = URL("https://example.com/enroll/totp")
    private val testEnabled = true
    private val testId = "totp-id-123"
    private val testAlgorithm = "SHA256"
    private val testSecret = "JBSWY3DPEHPK3PXP"
    private val testDigits = 6
    private val testPeriod = 30

    @Test
    fun constructor_withAllFields_shouldCreateInstance() {
        // When
        val factor = CloudTOTPEnrollableFactor(
            uri = testUri,
            type = EnrollableType.TOTP,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertEquals(testUri, factor.uri)
        assertEquals(EnrollableType.TOTP, factor.type)
        assertEquals(testEnabled, factor.enabled)
        assertEquals(testId, factor.id)
        assertEquals(testAlgorithm, factor.algorithm)
        assertEquals(testSecret, factor.secret)
        assertEquals(testDigits, factor.digits)
        assertEquals(testPeriod, factor.period)
    }

    @Test
    fun constructor_withDefaultType_shouldSetTOTP() {
        // When
        val factor = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertEquals(EnrollableType.TOTP, factor.type)
    }

    @Test
    fun constructor_withDifferentDigits_shouldSetDigits() {
        // When
        val factor8Digits = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = 8,
            period = testPeriod
        )

        // Then
        assertEquals(8, factor8Digits.digits)
    }

    @Test
    fun constructor_withDifferentPeriod_shouldSetPeriod() {
        // When
        val factor60Period = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = 60
        )

        // Then
        assertEquals(60, factor60Period.period)
    }

    @Test
    fun constructor_withSHA1Algorithm_shouldSetAlgorithm() {
        // When
        val factor = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = "SHA1",
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertEquals("SHA1", factor.algorithm)
    }

    @Test
    fun constructor_withSHA512Algorithm_shouldSetAlgorithm() {
        // When
        val factor = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = "SHA512",
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertEquals("SHA512", factor.algorithm)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.uri, copy.uri)
        assertEquals(original.type, copy.type)
        assertEquals(original.enabled, copy.enabled)
        assertEquals(original.id, copy.id)
        assertEquals(original.algorithm, copy.algorithm)
        assertEquals(original.secret, copy.secret)
        assertEquals(original.digits, copy.digits)
        assertEquals(original.period, copy.period)
    }

    @Test
    fun copy_withModifiedId_shouldUpdateOnlyId() {
        // Given
        val original = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // When
        val modified = original.copy(id = "new-id-456")

        // Then
        assertEquals("new-id-456", modified.id)
        assertEquals(original.uri, modified.uri)
        assertEquals(original.enabled, modified.enabled)
        assertEquals(original.algorithm, modified.algorithm)
        assertEquals(original.secret, modified.secret)
    }

    @Test
    fun copy_withModifiedSecret_shouldUpdateOnlySecret() {
        // Given
        val original = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // When
        val modified = original.copy(secret = "NEWSECRET123")

        // Then
        assertEquals("NEWSECRET123", modified.secret)
        assertEquals(original.id, modified.id)
        assertEquals(original.enabled, modified.enabled)
        assertEquals(original.algorithm, modified.algorithm)
    }

    @Test
    fun copy_withModifiedDigits_shouldUpdateOnlyDigits() {
        // Given
        val original = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // When
        val modified = original.copy(digits = 8)

        // Then
        assertEquals(8, modified.digits)
        assertEquals(original.period, modified.period)
    }

    @Test
    fun copy_withModifiedPeriod_shouldUpdateOnlyPeriod() {
        // Given
        val original = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // When
        val modified = original.copy(period = 60)

        // Then
        assertEquals(60, modified.period)
        assertEquals(original.digits, modified.digits)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val factor1 = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )
        val factor2 = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertEquals(factor1, factor2)
    }

    @Test
    fun equals_withDifferentId_shouldReturnFalse() {
        // Given
        val factor1 = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = "id1",
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )
        val factor2 = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = "id2",
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertNotEquals(factor1, factor2)
    }

    @Test
    fun equals_withDifferentSecret_shouldReturnFalse() {
        // Given
        val factor1 = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = "SECRET1",
            digits = testDigits,
            period = testPeriod
        )
        val factor2 = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = "SECRET2",
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertNotEquals(factor1, factor2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val factor1 = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )
        val factor2 = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertEquals(factor1.hashCode(), factor2.hashCode())
    }

    @Test
    fun toString_shouldContainAllProperties() {
        // Given
        val factor = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // When
        val result = factor.toString()

        // Then
        assert(result.contains("CloudTOTPEnrollableFactor"))
        assert(result.contains(testId))
        assert(result.contains(testAlgorithm))
        assert(result.contains(testDigits.toString()))
        assert(result.contains(testPeriod.toString()))
    }

    @Test
    fun implementsEnrollableFactor_shouldHaveUriTypeAndEnabled() {
        // Given
        val factor = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = testEnabled,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertNotNull(factor.uri)
        assertNotNull(factor.type)
        assertEquals(EnrollableType.TOTP, factor.type)
        assertEquals(testEnabled, factor.enabled)
    }

    @Test
    fun constructor_withVariousDigitValues_shouldSetCorrectly() {
        // Test common digit values
        val digits4 = CloudTOTPEnrollableFactor(testUri, EnrollableType.TOTP, testEnabled, testId, testAlgorithm, testSecret, 4, testPeriod)
        val digits6 = CloudTOTPEnrollableFactor(testUri, EnrollableType.TOTP, testEnabled, testId, testAlgorithm, testSecret, 6, testPeriod)
        val digits8 = CloudTOTPEnrollableFactor(testUri, EnrollableType.TOTP, testEnabled, testId, testAlgorithm, testSecret, 8, testPeriod)

        // Then
        assertEquals(4, digits4.digits)
        assertEquals(6, digits6.digits)
        assertEquals(8, digits8.digits)
    }

    @Test
    fun constructor_withVariousPeriodValues_shouldSetCorrectly() {
        // Test common period values
        val period15 = CloudTOTPEnrollableFactor(testUri, EnrollableType.TOTP, testEnabled, testId, testAlgorithm, testSecret, testDigits, 15)
        val period30 = CloudTOTPEnrollableFactor(testUri, EnrollableType.TOTP, testEnabled, testId, testAlgorithm, testSecret, testDigits, 30)
        val period60 = CloudTOTPEnrollableFactor(testUri, EnrollableType.TOTP, testEnabled, testId, testAlgorithm, testSecret, testDigits, 60)

        // Then
        assertEquals(15, period15.period)
        assertEquals(30, period30.period)
        assertEquals(60, period60.period)
    }

    @Test
    fun enabled_withTrueValue_shouldSetEnabled() {
        // When
        val factor = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = true,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertEquals(true, factor.enabled)
    }

    @Test
    fun enabled_withFalseValue_shouldSetEnabled() {
        // When
        val factor = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = false,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // Then
        assertEquals(false, factor.enabled)
    }

    @Test
    fun copy_withModifiedEnabled_shouldUpdateOnlyEnabled() {
        // Given
        val original = CloudTOTPEnrollableFactor(
            uri = testUri,
            enabled = true,
            id = testId,
            algorithm = testAlgorithm,
            secret = testSecret,
            digits = testDigits,
            period = testPeriod
        )

        // When
        val modified = original.copy(enabled = false)

        // Then
        assertEquals(false, modified.enabled)
        assertEquals(original.uri, modified.uri)
        assertEquals(original.type, modified.type)
        assertEquals(original.id, modified.id)
    }
}


