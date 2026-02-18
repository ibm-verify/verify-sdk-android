/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.core.VerifySdkException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class HashAlgorithmExceptionTest {

    @Test
    fun invalidHash_withoutCause_shouldCreateException() {
        // When
        val exception = HashAlgorithmException.InvalidHash()

        // Then
        assertNotNull(exception)
        assertTrue(exception is HashAlgorithmException)
        assertTrue(exception is VerifySdkException)
        assertNull(exception.cause)
    }

    @Test
    fun invalidHash_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = IllegalArgumentException("Test cause")

        // When
        val exception = HashAlgorithmException.InvalidHash(cause)

        // Then
        assertNotNull(exception)
        assertTrue(exception is HashAlgorithmException)
        assertTrue(exception is VerifySdkException)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun invalidHash_errorCode_shouldBeInvalidHashType() {
        // When
        val exception = HashAlgorithmException.InvalidHash()

        // Then
        assertEquals("invalid_hash_type", exception.error.id)
    }

    @Test
    fun invalidHash_errorMessage_shouldBeDescriptive() {
        // When
        val exception = HashAlgorithmException.InvalidHash()

        // Then
        assertEquals("The hash type is invalid.", exception.error.description)
    }

    @Test
    fun invalidHash_message_shouldContainErrorMessage() {
        // When
        val exception = HashAlgorithmException.InvalidHash()

        // Then
        assertNotNull(exception.message)
        assertTrue(exception.message?.contains("The hash type is invalid.") == true)
    }

    @Test
    fun invalidHash_withCause_messageShouldContainCauseInfo() {
        // Given
        val cause = IllegalArgumentException("Invalid algorithm name")

        // When
        val exception = HashAlgorithmException.InvalidHash(cause)

        // Then
        assertNotNull(exception.message)
        assertNotNull(exception.cause)
        assertEquals("Invalid algorithm name", exception.cause?.message)
    }

    @Test
    fun invalidHash_isThrowable_shouldBeThrowable() {
        // When
        val exception = HashAlgorithmException.InvalidHash()

        // Then
        assertTrue(exception is Throwable)
    }

    @Test
    fun invalidHash_canBeThrown_shouldBeCatchable() {
        // Given
        var caughtException: HashAlgorithmException.InvalidHash? = null

        // When
        try {
            throw HashAlgorithmException.InvalidHash()
        } catch (e: HashAlgorithmException.InvalidHash) {
            caughtException = e
        }

        // Then
        assertNotNull(caughtException)
        assertTrue(caughtException is HashAlgorithmException.InvalidHash)
    }

    @Test
    fun invalidHash_canBeCaughtAsHashAlgorithmException() {
        // Given
        var caughtException: HashAlgorithmException? = null

        // When
        try {
            throw HashAlgorithmException.InvalidHash()
        } catch (e: HashAlgorithmException) {
            caughtException = e
        }

        // Then
        assertNotNull(caughtException)
        assertTrue(caughtException is HashAlgorithmException.InvalidHash)
    }

    @Test
    fun invalidHash_canBeCaughtAsVerifySdkException() {
        // Given
        var caughtException: VerifySdkException? = null

        // When
        try {
            throw HashAlgorithmException.InvalidHash()
        } catch (e: VerifySdkException) {
            caughtException = e
        }

        // Then
        assertNotNull(caughtException)
        assertTrue(caughtException is HashAlgorithmException.InvalidHash)
    }

    @Test
    fun invalidHash_canBeCaughtAsException() {
        // Given
        var caughtException: Exception? = null

        // When
        try {
            throw HashAlgorithmException.InvalidHash()
        } catch (e: Exception) {
            caughtException = e
        }

        // Then
        assertNotNull(caughtException)
        assertTrue(caughtException is HashAlgorithmException.InvalidHash)
    }

    @Test
    fun invalidHash_stackTrace_shouldBeAvailable() {
        // When
        val exception = HashAlgorithmException.InvalidHash()

        // Then
        assertNotNull(exception.stackTrace)
        assertTrue(exception.stackTrace.isNotEmpty())
    }

    @Test
    fun invalidHash_withNestedCause_shouldPreserveCauseChain() {
        // Given
        val rootCause = RuntimeException("Root cause")
        val intermediateCause = IllegalArgumentException("Intermediate cause", rootCause)

        // When
        val exception = HashAlgorithmException.InvalidHash(intermediateCause)

        // Then
        assertNotNull(exception.cause)
        assertEquals(intermediateCause, exception.cause)
        assertNotNull(exception.cause?.cause)
        assertEquals(rootCause, exception.cause?.cause)
    }

    @Test
    fun invalidHash_toString_shouldContainErrorInformation() {
        // When
        val exception = HashAlgorithmException.InvalidHash()
        val result = exception.toString()

        // Then
        assertNotNull(result)
        assertTrue(result.contains("InvalidHash") || result.contains("HashAlgorithmException"))
        assertTrue(result.contains("invalid_hash_type"))
        assertTrue(result.contains("The hash type is invalid."))
    }

    @Test
    fun invalidHash_multipleInstances_shouldBeIndependent() {
        // Given
        val cause1 = IllegalArgumentException("Cause 1")
        val cause2 = IllegalArgumentException("Cause 2")

        // When
        val exception1 = HashAlgorithmException.InvalidHash(cause1)
        val exception2 = HashAlgorithmException.InvalidHash(cause2)

        // Then
        assertEquals(cause1, exception1.cause)
        assertEquals(cause2, exception2.cause)
        assertEquals("invalid_hash_type", exception1.error.id)
        assertEquals("invalid_hash_type", exception2.error.id)
    }

    @Test
    fun sealedClass_onlyInvalidHashSubclass_shouldExist() {
        // Given
        val exception: HashAlgorithmException = HashAlgorithmException.InvalidHash()

        // When/Then - Verify sealed class behavior
        when (exception) {
            is HashAlgorithmException.InvalidHash -> {
                // Expected subclass
                assertTrue(true)
            }
        }
    }

    @Test
    fun invalidHash_errorObject_shouldBeAccessible() {
        // When
        val exception = HashAlgorithmException.InvalidHash()
        val error = exception.error

        // Then
        assertNotNull(error)
        assertEquals("invalid_hash_type", error.id)
        assertEquals("The hash type is invalid.", error.description)
    }

    @Test
    fun invalidHash_withDifferentCauses_shouldMaintainDistinctCauses() {
        // Given
        val nullPointerCause = NullPointerException("Null value")
        val illegalStateCause = IllegalStateException("Invalid state")

        // When
        val exception1 = HashAlgorithmException.InvalidHash(nullPointerCause)
        val exception2 = HashAlgorithmException.InvalidHash(illegalStateCause)

        // Then
        assertTrue(exception1.cause is NullPointerException)
        assertTrue(exception2.cause is IllegalStateException)
        assertEquals("Null value", exception1.cause?.message)
        assertEquals("Invalid state", exception2.cause?.message)
    }
}

