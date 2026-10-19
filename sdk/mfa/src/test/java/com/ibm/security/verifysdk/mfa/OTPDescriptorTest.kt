/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class OTPDescriptorTest {

    private val baseSecret = "JBSWY3DPEHPK3PXP"
    private val fixedTimestamp = 1580608922L // 2020-02-02 02:02:02 UTC

    @Test
    fun generatePasscode_standardBase32Secret_generatesCorrectPasscode() {
        val totp = TOTPFactorInfo(secret = baseSecret, period = 24)
        val passcode = totp.generatePasscode(fixedTimestamp)
        assertEquals("610436", passcode)
    }

    @Test
    fun generatePasscode_dashedSecret_generatesSamePasscodeAsStandardSecret() {
        val standardTotp = TOTPFactorInfo(secret = baseSecret, period = 30)
        val dashedTotp = TOTPFactorInfo(secret = "JBSW-Y3DP-EHPK-3PXP", period = 30)

        val expectedPasscode = standardTotp.generatePasscode(fixedTimestamp)
        val dashedPasscode = dashedTotp.generatePasscode(fixedTimestamp)

        assertEquals(expectedPasscode, dashedPasscode)
    }

    @Test
    fun generatePasscode_spacedSecret_generatesSamePasscodeAsStandardSecret() {
        val standardTotp = TOTPFactorInfo(secret = baseSecret, period = 30)
        val spacedTotp = TOTPFactorInfo(secret = "JBSW Y3DP EHPK 3PXP", period = 30)

        val expectedPasscode = standardTotp.generatePasscode(fixedTimestamp)
        val spacedPasscode = spacedTotp.generatePasscode(fixedTimestamp)

        assertEquals(expectedPasscode, spacedPasscode)
    }

    @Test
    fun generatePasscode_lowercaseSecret_generatesSamePasscodeAsStandardSecret() {
        val standardTotp = TOTPFactorInfo(secret = baseSecret, period = 30)
        val lowercaseTotp = TOTPFactorInfo(secret = "jbswy3dpehpk3pxp", period = 30)

        val expectedPasscode = standardTotp.generatePasscode(fixedTimestamp)
        val lowercasePasscode = lowercaseTotp.generatePasscode(fixedTimestamp)

        assertEquals(expectedPasscode, lowercasePasscode)
    }

    @Test
    fun generatePasscode_paddedSecret_generatesSamePasscodeAsUnpaddedSecret() {
        val unpaddedTotp = TOTPFactorInfo(secret = "MZXW6YTB", period = 30)
        val paddedTotp = TOTPFactorInfo(secret = "MZXW6YTB====", period = 30)

        val expectedPasscode = unpaddedTotp.generatePasscode(fixedTimestamp)
        val paddedPasscode = paddedTotp.generatePasscode(fixedTimestamp)

        assertEquals(expectedPasscode, paddedPasscode)
    }

    @Test
    fun generatePasscode_combinedFormattedSecret_generatesSamePasscodeAsStandardSecret() {
        val standardTotp = TOTPFactorInfo(secret = baseSecret, period = 30)
        val combinedTotp = TOTPFactorInfo(secret = "  jbsw-y3dp \t ehpk-3pxp== \n", period = 30)

        val expectedPasscode = standardTotp.generatePasscode(fixedTimestamp)
        val combinedPasscode = combinedTotp.generatePasscode(fixedTimestamp)

        assertEquals(expectedPasscode, combinedPasscode)
    }

    @Test
    fun generatePasscode_invalidCharacters_throwsMFAServiceExceptionGeneral() {
        val invalidTotp = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PX8", period = 30) // '8' is not in Base32 alphabet

        val exception = assertThrows(MFAServiceException.General::class.java) {
            invalidTotp.generatePasscode(fixedTimestamp)
        }

        assertEquals("general_mfa_error", exception.error.id)
        assertEquals("Invalid Base32 secret key.", exception.error.description)
        assertNotNull(exception.cause)
        assertTrue(exception.cause is IllegalArgumentException)
    }

    @Test
    fun generatePasscode_uuidOrNonBase32Secret_throwsMFAServiceExceptionGeneral() {
        val uuidSecretTotp = TOTPFactorInfo(secret = "8f9e1234-abcd-ef01-2345-6789abcdef01", period = 30)

        val exception = assertThrows(MFAServiceException.General::class.java) {
            uuidSecretTotp.generatePasscode(fixedTimestamp)
        }

        assertEquals("general_mfa_error", exception.error.id)
        assertTrue(exception.cause is IllegalArgumentException)
    }

    @Test
    fun generatePasscode_emptySecret_throwsMFAServiceExceptionGeneral() {
        val emptySecretTotp = TOTPFactorInfo(secret = "", period = 30)

        val exception = assertThrows(MFAServiceException.General::class.java) {
            emptySecretTotp.generatePasscode(fixedTimestamp)
        }

        assertEquals("general_mfa_error", exception.error.id)
        assertEquals("Secret key cannot be empty.", exception.error.description)
    }

    @Test
    fun generatePasscode_whitespaceOnlySecret_throwsMFAServiceExceptionGeneral() {
        val whitespaceTotp = TOTPFactorInfo(secret = "   \t\n   ", period = 30)

        val exception = assertThrows(MFAServiceException.General::class.java) {
            whitespaceTotp.generatePasscode(fixedTimestamp)
        }

        assertEquals("general_mfa_error", exception.error.id)
        assertEquals("Secret key cannot be empty.", exception.error.description)
    }

    @Test
    fun generatePasscode_dashesOnlySecret_throwsMFAServiceExceptionGeneral() {
        val dashesTotp = TOTPFactorInfo(secret = "---", period = 30)

        val exception = assertThrows(MFAServiceException.General::class.java) {
            dashesTotp.generatePasscode(fixedTimestamp)
        }

        assertEquals("general_mfa_error", exception.error.id)
        assertEquals("Secret key cannot be empty.", exception.error.description)
    }

    @Test
    fun fromQRScan_emptyOrBlankSecret_returnsNull() {
        val emptySecretUri = "otpauth://totp/Test:user?secret=&period=30"
        val blankSecretUri = "otpauth://totp/Test:user?secret=%20%20&period=30"

        assertEquals(null, OTPAuthenticator.fromQRScan(emptySecretUri))
        assertEquals(null, OTPAuthenticator.fromQRScan(blankSecretUri))
    }

    @Test
    fun hotp_generatePasscode_withDashedSecret_generatesCorrectPasscodeAndIncrementsCounter() {
        val standardHotp = HOTPFactorInfo(secret = baseSecret)
        val dashedHotp = HOTPFactorInfo(secret = "JBSW-Y3DP-EHPK-3PXP")

        val expectedCode1 = standardHotp.generatePasscode(incrementCounter = true)
        val dashedCode1 = dashedHotp.generatePasscode(incrementCounter = true)
        assertEquals(expectedCode1, dashedCode1)
        assertEquals(1, dashedHotp.counter)

        val expectedCode2 = standardHotp.generatePasscode(incrementCounter = true)
        val dashedCode2 = dashedHotp.generatePasscode(incrementCounter = true)
        assertEquals(expectedCode2, dashedCode2)
        assertEquals(2, dashedHotp.counter)
    }

    @Test
    fun hotp_generatePasscode_withInvalidSecret_throwsExceptionAndDoesNotIncrementCounter() {
        val invalidHotp = HOTPFactorInfo(secret = "INVALID-8901!")

        assertThrows(MFAServiceException.General::class.java) {
            invalidHotp.generatePasscode()
        }
        assertEquals(0, invalidHotp.counter)
    }
}
