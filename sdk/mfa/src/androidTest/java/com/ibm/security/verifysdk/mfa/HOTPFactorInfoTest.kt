/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith


@RunWith(AndroidJUnit4::class)
class HOTPFactorInfoTest {

    private val secret = "ON6MJUIM4MXYVLN3"

    @Test
    fun generatePasscode_happyPath_shouldGeneratePasscode() {

        val values = listOf("488394","643724","156322","759595","629686","015146","844528","971941","855801","409719","233609")
        val factor =
            HOTPFactorInfo(secret = secret)

        for (i in 0 until 10) {
            val result = factor.generatePasscode(i.toLong())
            assertEquals(6, result.length)
            assertEquals(values[i], result)
        }
    }

    @Test
    fun generatePasscode_withInternalCounter_shouldGeneratePasscode() {

        val values = listOf("488394","643724","156322","759595","629686","015146","844528","971941","855801","409719","233609")
        val factor =
            HOTPFactorInfo(secret = secret)

        for (i in 0 until 10) {
            val result = factor.generatePasscode()
            assertEquals(6, result.length)
            assertEquals(values[i], result)
        }
    }

    @Test
    fun generatePasscode_withDigits3_shouldGeneratePasscodes() {

        val values = listOf("394","724","322","595","686","146","528","941","801","719","609")
        val factor =
            HOTPFactorInfo(secret = secret, digits = 3)

        for (i in 0 until 10) {
            val result = factor.generatePasscode(i.toLong())
            assertEquals(3, result.length)
            assertEquals(values[i], result)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun constructor_withDigits0_shouldThrowException() {
        val factor =
            HOTPFactorInfo(secret = secret, digits = 0)
    }

    @Test
    fun constructor_withDigits6_shouldBeAccepted() {
        val factor =
            HOTPFactorInfo(secret = secret, digits = 6)
        assertEquals(6, factor.digits)
    }

    @Test(expected = IllegalArgumentException::class)
    fun constructor_withDigits7_shouldThrowException() {
        val factor =
            HOTPFactorInfo(secret = secret, digits = 7)
    }

    @Test
    fun constructor_withDigits8_shouldBeAccepted() {
        val factor =
            HOTPFactorInfo(secret = secret, digits = 8)
        assertEquals(8, factor.digits)
    }

    @Test(expected = IllegalArgumentException::class)
    fun constructor_withDigits9_shouldBeAccepted() {
        val factor =
            HOTPFactorInfo(secret = secret, digits = 9)
    }

    @Test
    fun generatePasscode_withIncrementCounterTrue_shouldIncrementCounter() {
        val factor = HOTPFactorInfo(secret = secret)
        
        // Initial counter should be 0
        assertEquals(0, factor.counter)
        
        // Generate passcode with incrementCounter = true
        val passcode1 = factor.generatePasscode(incrementCounter = true)
        assertEquals("488394", passcode1)
        assertEquals(1, factor.counter)
        
        // Generate another passcode with incrementCounter = true
        val passcode2 = factor.generatePasscode(incrementCounter = true)
        assertEquals("643724", passcode2)
        assertEquals(2, factor.counter)
    }

    @Test
    fun generatePasscode_withIncrementCounterFalse_shouldNotIncrementCounter() {
        val factor = HOTPFactorInfo(secret = secret)
        
        // Initial counter should be 0
        assertEquals(0, factor.counter)
        
        // Generate passcode with incrementCounter = false
        val passcode1 = factor.generatePasscode(incrementCounter = false)
        assertEquals("488394", passcode1)
        assertEquals(0, factor.counter) // Counter should remain 0
        
        // Generate another passcode with incrementCounter = false
        val passcode2 = factor.generatePasscode(incrementCounter = false)
        assertEquals("488394", passcode2) // Should be the same passcode
        assertEquals(0, factor.counter) // Counter should still be 0
    }

    @Test
    fun generatePasscode_mixedIncrementBehavior_shouldWorkCorrectly() {
        val factor = HOTPFactorInfo(secret = secret)
        
        // Preview without incrementing
        val preview1 = factor.generatePasscode(incrementCounter = false)
        assertEquals("488394", preview1)
        assertEquals(0, factor.counter)
        
        // Actually generate and increment
        val actual1 = factor.generatePasscode(incrementCounter = true)
        assertEquals("488394", actual1)
        assertEquals(1, factor.counter)
        
        // Preview the next one without incrementing
        val preview2 = factor.generatePasscode(incrementCounter = false)
        assertEquals("643724", preview2)
        assertEquals(1, factor.counter)
        
        // Preview again - should be the same
        val preview3 = factor.generatePasscode(incrementCounter = false)
        assertEquals("643724", preview3)
        assertEquals(1, factor.counter)
        
        // Actually generate and increment
        val actual2 = factor.generatePasscode(incrementCounter = true)
        assertEquals("643724", actual2)
        assertEquals(2, factor.counter)
    }

    @Test
    fun generatePasscode_withIncrementCounterFalse_multipleCallsShouldReturnSamePasscode() {
        val factor = HOTPFactorInfo(secret = secret)
        
        // Call multiple times with incrementCounter = false
        for (i in 0 until 5) {
            val passcode = factor.generatePasscode(incrementCounter = false)
            assertEquals("488394", passcode)
            assertEquals(0, factor.counter)
        }
    }

    @Test
    fun generatePasscode_withIncrementCounterTrue_shouldMatchSequentialGeneration() {
        val factor = HOTPFactorInfo(secret = secret)
        val values = listOf("488394","643724","156322","759595","629686")
        
        for (i in 0 until 5) {
            val passcode = factor.generatePasscode(incrementCounter = true)
            assertEquals(values[i], passcode)
            assertEquals(i + 1, factor.counter)
        }
    }

    @Test
    fun generatePasscode_withIncrementCounterAndCustomDigits_shouldWorkCorrectly() {
        val factor = HOTPFactorInfo(secret = secret, digits = 8)
        
        // Preview with 8 digits
        val preview = factor.generatePasscode(incrementCounter = false)
        assertEquals(8, preview.length)
        assertEquals(0, factor.counter)
        
        // Generate with increment
        val actual = factor.generatePasscode(incrementCounter = true)
        assertEquals(8, actual.length)
        assertEquals(preview, actual) // Should be the same value
        assertEquals(1, factor.counter)
    }
}