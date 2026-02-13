/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OTPAuthenticatorTest {

    @Test
    fun constructor_withTOTP_shouldCreateInstance() {
        // Given
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")

        // When
        val authenticator = OTPAuthenticator(
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )

        // Then
        assertNotNull(authenticator.id)
        assertEquals("TestService", authenticator.serviceName)
        assertEquals("test@example.com", authenticator.accountName)
        assertEquals(totp, authenticator.totp)
        assertNull(authenticator.hotp)
    }

    @Test
    fun constructor_withHOTP_shouldCreateInstance() {
        // Given
        val hotp = HOTPFactorInfo(secret = "ON6MJUIM4MXYVLN3")

        // When
        val authenticator = OTPAuthenticator(
            serviceName = "TestService",
            accountName = "test@example.com",
            hotp = hotp
        )

        // Then
        assertNotNull(authenticator.id)
        assertEquals("TestService", authenticator.serviceName)
        assertEquals("test@example.com", authenticator.accountName)
        assertNull(authenticator.totp)
        assertEquals(hotp, authenticator.hotp)
    }

    @Test
    fun constructor_withCustomId_shouldSetId() {
        // Given
        val customId = "custom-id-123"
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")

        // When
        val authenticator = OTPAuthenticator(
            id = customId,
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )

        // Then
        assertEquals(customId, authenticator.id)
    }

    @Test(expected = IllegalArgumentException::class)
    fun constructor_withoutTOTPOrHOTP_shouldThrowException() {
        // When
        OTPAuthenticator(
            serviceName = "TestService",
            accountName = "test@example.com"
        )
    }

    @Test
    fun constructor_withBothTOTPAndHOTP_shouldCreateInstance() {
        // Given
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val hotp = HOTPFactorInfo(secret = "ON6MJUIM4MXYVLN3")

        // When
        val authenticator = OTPAuthenticator(
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp,
            hotp = hotp
        )

        // Then
        assertNotNull(authenticator.totp)
        assertNotNull(authenticator.hotp)
    }

    @Test
    fun fromQRScan_withValidTOTPUri_shouldCreateAuthenticator() {
        // Given
        val qrCode = "otpauth://totp/TestService:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNotNull(authenticator)
        assertEquals("TestService", authenticator?.serviceName)
        assertEquals("user@example.com", authenticator?.accountName)
        assertNotNull(authenticator?.totp)
        assertNull(authenticator?.hotp)
    }

    @Test
    fun fromQRScan_withValidHOTPUri_shouldCreateAuthenticator() {
        // Given
        val qrCode = "otpauth://hotp/TestService:user@example.com?secret=ON6MJUIM4MXYVLN3&algorithm=SHA1&digits=6&counter=0"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNotNull(authenticator)
        assertEquals("TestService", authenticator?.serviceName)
        assertEquals("user@example.com", authenticator?.accountName)
        assertNull(authenticator?.totp)
        assertNotNull(authenticator?.hotp)
    }

    @Test
    fun fromQRScan_withInvalidUri_shouldReturnNull() {
        // Given
        val qrCode = "invalid://uri"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNull(authenticator)
    }

    @Test
    fun fromQRScan_withMissingSecret_shouldReturnNull() {
        // Given
        val qrCode = "otpauth://totp/TestService:user@example.com?algorithm=SHA1&digits=6&period=30"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNull(authenticator)
    }

    @Test
    fun fromQRScan_withSHA256Algorithm_shouldCreateAuthenticator() {
        // Given
        val qrCode = "otpauth://totp/TestService:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNotNull(authenticator)
        assertEquals(HashAlgorithmType.SHA256, authenticator?.totp?.algorithm)
    }

    @Test
    fun fromQRScan_with8Digits_shouldCreateAuthenticator() {
        // Given
        val qrCode = "otpauth://totp/TestService:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=8&period=30"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNotNull(authenticator)
        assertEquals(8, authenticator?.totp?.digits)
    }

    @Test
    fun fromQRScan_withCustomPeriod_shouldCreateAuthenticator() {
        // Given
        val qrCode = "otpauth://totp/TestService:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=60"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNotNull(authenticator)
        assertEquals(60, authenticator?.totp?.period)
    }

    @Test
    fun fromQRScan_withPercentEncodedLabel_shouldDecodeCorrectly() {
        // Given
        val qrCode = "otpauth://totp/Test%20Service:user%40example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNotNull(authenticator)
        assertEquals("Test Service", authenticator?.serviceName)
        assertEquals("user@example.com", authenticator?.accountName)
    }

    @Test
    fun fromQRScan_withOnlyServiceName_shouldUseServiceNameAsAccountName() {
        // Given
        val qrCode = "otpauth://totp/TestService?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&period=30"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNotNull(authenticator)
        assertEquals("TestService", authenticator?.serviceName)
        assertEquals("TestService", authenticator?.accountName)
    }

    @Test
    fun fromQRScan_withDefaultValues_shouldUseDefaults() {
        // Given - Minimal QR code with only required parameters
        val qrCode = "otpauth://totp/TestService:user@example.com?secret=JBSWY3DPEHPK3PXP"

        // When
        val authenticator = OTPAuthenticator.fromQRScan(qrCode)

        // Then
        assertNotNull(authenticator)
        assertEquals(6, authenticator?.totp?.digits)
        assertEquals(30, authenticator?.totp?.period)
        assertEquals(HashAlgorithmType.SHA1, authenticator?.totp?.algorithm)
    }

    @Test
    fun serialization_withTOTP_shouldSerializeAndDeserialize() {
        // Given
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val authenticator = OTPAuthenticator(
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(authenticator)
        val deserialized = json.decodeFromString<OTPAuthenticator>(serialized)

        // Then
        assertEquals(authenticator.id, deserialized.id)
        assertEquals(authenticator.serviceName, deserialized.serviceName)
        assertEquals(authenticator.accountName, deserialized.accountName)
        assertNotNull(deserialized.totp)
        assertNull(deserialized.hotp)
    }

    @Test
    fun serialization_withHOTP_shouldSerializeAndDeserialize() {
        // Given
        val hotp = HOTPFactorInfo(secret = "ON6MJUIM4MXYVLN3")
        val authenticator = OTPAuthenticator(
            serviceName = "TestService",
            accountName = "test@example.com",
            hotp = hotp
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(authenticator)
        val deserialized = json.decodeFromString<OTPAuthenticator>(serialized)

        // Then
        assertEquals(authenticator.id, deserialized.id)
        assertEquals(authenticator.serviceName, deserialized.serviceName)
        assertEquals(authenticator.accountName, deserialized.accountName)
        assertNull(deserialized.totp)
        assertNotNull(deserialized.hotp)
    }

    @Test
    fun implementsAuthenticatorDescriptor_shouldHaveRequiredProperties() {
        // Given
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val authenticator: AuthenticatorDescriptor = OTPAuthenticator(
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )

        // Then
        assertNotNull(authenticator.id)
        assertNotNull(authenticator.serviceName)
        assertNotNull(authenticator.accountName)
    }

    @Test
    fun accountName_shouldBeMutable() {
        // Given
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val authenticator = OTPAuthenticator(
            serviceName = "TestService",
            accountName = "original@example.com",
            totp = totp
        )

        // When
        authenticator.accountName = "updated@example.com"

        // Then
        assertEquals("updated@example.com", authenticator.accountName)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val original = OTPAuthenticator(
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.id, copy.id)
        assertEquals(original.serviceName, copy.serviceName)
        assertEquals(original.accountName, copy.accountName)
        assertEquals(original.totp, copy.totp)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val id = "test-id"
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val authenticator1 = OTPAuthenticator(
            id = id,
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )
        val authenticator2 = OTPAuthenticator(
            id = id,
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )

        // Then
        assertEquals(authenticator1, authenticator2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val id = "test-id"
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val authenticator1 = OTPAuthenticator(
            id = id,
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )
        val authenticator2 = OTPAuthenticator(
            id = id,
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )

        // Then
        assertEquals(authenticator1.hashCode(), authenticator2.hashCode())
    }

    @Test
    fun toString_shouldContainAuthenticatorInformation() {
        // Given
        val totp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val authenticator = OTPAuthenticator(
            serviceName = "TestService",
            accountName = "test@example.com",
            totp = totp
        )

        // When
        val result = authenticator.toString()

        // Then
        assertTrue(result.contains("OTPAuthenticator"))
    }
}
