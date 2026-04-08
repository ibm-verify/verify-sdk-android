/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Basic test cases for [VerifySdkException].
 */
@RunWith(AndroidJUnit4::class)
class VerifySdkExceptionTest {

    @Test
    fun testExceptionWithError() {
        val error = Error("TEST_ERROR", "Test error message")
        val exception = VerifySdkException(error)
        
        assertEquals("Test error message", exception.message)
        assertEquals(error, exception.error)
        assertNull(exception.cause)
    }

    @Test
    fun testExceptionWithErrorAndCause() {
        val error = Error("TEST_ERROR", "Test error message")
        val cause = IllegalArgumentException("Root cause")
        val exception = VerifySdkException(error, cause)
        
        assertEquals("Test error message", exception.message)
        assertEquals(error, exception.error)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun testExceptionCanBeThrown() {
        val error = Error("TEST_ERROR", "Test exception")
        try {
            throw VerifySdkException(error)
        } catch (e: VerifySdkException) {
            assertEquals("Test exception", e.message)
            assertEquals("TEST_ERROR", e.error.id)
        }
    }

    @Test
    fun testExceptionChaining() {
        val rootCause = IllegalArgumentException("Root")
        val middleError = Error("MIDDLE_ERROR", "Middle")
        val middleCause = VerifySdkException(middleError, rootCause)
        val topError = Error("TOP_ERROR", "Top")
        val topException = VerifySdkException(topError, middleCause)
        
        assertEquals("Top", topException.message)
        assertEquals("TOP_ERROR", topException.error.id)
        assertEquals(middleCause, topException.cause)
        assertEquals(rootCause, topException.cause?.cause)
    }

    @Test
    fun testExceptionToString() {
        val error = Error("TEST_ERROR", "Test description")
        val exception = VerifySdkException(error)
        
        val string = exception.toString()
        assertTrue(string.contains("TEST_ERROR"))
        assertTrue(string.contains("Test description"))
    }

    @Test
    fun testExceptionToStringWithCause() {
        val error = Error("TEST_ERROR", "Test description")
        val cause = IllegalArgumentException("Root cause")
        val exception = VerifySdkException(error, cause)
        
        val string = exception.toString()
        assertTrue(string.contains("TEST_ERROR"))
        assertTrue(string.contains("Test description"))
        assertTrue(string.contains("Root cause"))
    }

    @Test
    fun testErrorDataClass() {
        val error1 = Error("ERROR_1", "Description 1")
        val error2 = Error("ERROR_1", "Description 1")
        val error3 = Error("ERROR_2", "Description 2")
        
        assertEquals(error1, error2)
        assertNotEquals(error1, error3)
        assertEquals(error1.hashCode(), error2.hashCode())
    }
}
