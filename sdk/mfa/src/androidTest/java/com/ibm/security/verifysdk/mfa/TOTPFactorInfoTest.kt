/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TOTPFactorInfoTest {

    private val secret = "JBSWY3DPEHPK3PXP"

    @Suppress("LocalVariableName")
    @Test
    fun generatePasscode_withPeriod24_shouldGeneratePasscode() {

        val T19980303_013448_UTC = 888888888L
        val T20000101_000000_UTC = 946684800L
        val T20200202_020202_UTC = 1580608922L
        val factor = TOTPFactorInfo(secret = secret, period = 24)

        assertEquals("358462", factor.generatePasscode(T19980303_013448_UTC))
        assertEquals("181988", factor.generatePasscode(T20000101_000000_UTC))
        assertEquals("610436", factor.generatePasscode(T20200202_020202_UTC))
    }

    @Test
    fun generatePasscode_withDigits2Sha512_shouldGeneratePasscode() {

        val period = 30
        val values = listOf("88", "87", "71", "55", "99", "60", "39", "35", "99", "12")
        val factor =
            TOTPFactorInfo(secret = secret, digits = 2, algorithm = HashAlgorithmType.SHA512)

        for (i in 0 until 10) {
            val result = factor.generatePasscode(i.toLong() * period)
            assertEquals(2, result.length)
            assertEquals(values[i], result)
        }
    }

    @Test
    fun generatePasscode_withDigits3_shouldGeneratePasscodes() {

        val period = 30
        val values = listOf("760", "554", "287", "627", "129", "897", "951", "891", "230", "769")
        val factor = TOTPFactorInfo(secret = secret, digits = 3)

        for (i in 0 until 10) {
            val result = factor.generatePasscode(i.toLong() * period)
            assertEquals(3, result.length)
            assertEquals(values[i], result)
        }
    }

    @Test
    fun generatePasscode_withDigits5Sha512_shouldGeneratePasscode() {

        val period = 30
        val values = listOf(
            "82788",
            "39887",
            "44671",
            "29955",
            "08699",
            "23460",
            "73439",
            "75035",
            "31699",
            "99912"
        )
        val factor =
            TOTPFactorInfo(secret = secret, digits = 5, algorithm = HashAlgorithmType.SHA512)

        for (i in 0 until 10) {
            val result = factor.generatePasscode(i.toLong() * period)
            assertEquals(5, result.length)
            assertEquals(values[i], result)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun constructor_withDigits0_shouldThrowException() {
        val factor =
            TOTPFactorInfo(secret = secret, digits = 0)
    }

    @Test
    fun constructor_withDigits6_shouldBeAccepted() {
        val factor =
            TOTPFactorInfo(secret = secret, digits = 6)
        assertEquals(6, factor.digits)
    }

    @Test(expected = IllegalArgumentException::class)
    fun constructor_withDigits7_shouldThrowException() {
        val factor =
            TOTPFactorInfo(secret = secret, digits = 7)
    }

    @Test
    fun constructor_withDigits8_shouldBeAccepted() {
        val factor =
            TOTPFactorInfo(secret = secret, digits = 8)
        assertEquals(8, factor.digits)
    }

    @Test(expected = IllegalArgumentException::class)
    fun constructor_withDigits9_shouldBeAccepted() {
        val factor =
            TOTPFactorInfo(secret = secret, digits = 9)
    }

    @Test(expected = IllegalArgumentException::class)
    fun constructor_withPeriod9_shouldThrowException() {
        val factor =
            TOTPFactorInfo(secret = secret, period = 9)
    }

    @Test(expected = IllegalArgumentException::class)
    fun constructor_withPeriod301_shouldThrowException() {
        val factor =
            TOTPFactorInfo(secret = secret, period = 301)
    }
}