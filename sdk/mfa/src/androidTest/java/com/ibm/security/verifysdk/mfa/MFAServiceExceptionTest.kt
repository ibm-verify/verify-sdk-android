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
class MFAServiceExceptionTest {

    @Test
    fun invalidSigningHash_withoutCause_shouldCreateException() {
        // When
        val exception = MFAServiceException.InvalidSigningHash()

        // Then
        assertNotNull(exception)
        assertTrue(exception is MFAServiceException)
        assertTrue(exception is VerifySdkException)
        assertNull(exception.cause)
        assertEquals("invalid_signing_hash", exception.error.id)
        assertEquals("The signing hash algorithm was invalid.", exception.error.description)
    }

    @Test
    fun invalidSigningHash_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = IllegalArgumentException("Invalid hash")

        // When
        val exception = MFAServiceException.InvalidSigningHash(cause)

        // Then
        assertEquals(cause, exception.cause)
        assertEquals("invalid_signing_hash", exception.error.id)
    }

    @Test
    fun invalidPendingTransaction_withoutCause_shouldCreateException() {
        // When
        val exception = MFAServiceException.InvalidPendingTransaction()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("invalid_pending_transaction", exception.error.id)
        assertEquals("No pending transaction was available to complete.", exception.error.description)
    }

    @Test
    fun invalidPendingTransaction_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = RuntimeException("Transaction error")

        // When
        val exception = MFAServiceException.InvalidPendingTransaction(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun serializationFailed_withoutCause_shouldCreateException() {
        // When
        val exception = MFAServiceException.SerializationFailed()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("serialization_failed", exception.error.id)
        assertEquals("Serialization conversion failed.", exception.error.description)
    }

    @Test
    fun serializationFailed_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = IllegalStateException("Serialization error")

        // When
        val exception = MFAServiceException.SerializationFailed(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun invalidDataResponse_withoutCause_shouldCreateException() {
        // When
        val exception = MFAServiceException.InvalidDataResponse()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("invalid_data_response", exception.error.id)
        assertEquals("The response data was invalid.", exception.error.description)
    }

    @Test
    fun invalidDataResponse_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = Exception("Invalid response")

        // When
        val exception = MFAServiceException.InvalidDataResponse(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun decodingFailed_withoutCause_shouldCreateException() {
        // When
        val exception = MFAServiceException.DecodingFailed()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("decoding_failed", exception.error.id)
        assertEquals("The JSON decoding operation failed.", exception.error.description)
    }

    @Test
    fun decodingFailed_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = NullPointerException("Null JSON")

        // When
        val exception = MFAServiceException.DecodingFailed(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun unableToCreateTransaction_withoutCause_shouldCreateException() {
        // When
        val exception = MFAServiceException.UnableToCreateTransaction()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("unable_to_create_transaction", exception.error.id)
        assertEquals("Unable to create the pending transaction.", exception.error.description)
    }

    @Test
    fun unableToCreateTransaction_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = IllegalArgumentException("Creation failed")

        // When
        val exception = MFAServiceException.UnableToCreateTransaction(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun general_withDescription_shouldCreateException() {
        // Given
        val description = "Custom MFA error"

        // When
        val exception = MFAServiceException.General(description)

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("general_mfa_error", exception.error.id)
        assertEquals(description, exception.error.description)
    }

    @Test
    fun general_withDescriptionAndCause_shouldCreateExceptionWithCause() {
        // Given
        val description = "Custom error with cause"
        val cause = RuntimeException("Root cause")

        // When
        val exception = MFAServiceException.General(description, cause)

        // Then
        assertEquals(cause, exception.cause)
        assertEquals(description, exception.error.description)
    }

    @Test
    fun allExceptions_canBeCaughtAsMFAServiceException() {
        // Given
        val exceptions = listOf(
            MFAServiceException.InvalidSigningHash(),
            MFAServiceException.InvalidPendingTransaction(),
            MFAServiceException.SerializationFailed(),
            MFAServiceException.InvalidDataResponse(),
            MFAServiceException.DecodingFailed(),
            MFAServiceException.UnableToCreateTransaction(),
            MFAServiceException.General("Test")
        )

        // When/Then
        for (exception in exceptions) {
            assertTrue(exception is MFAServiceException)
            assertTrue(exception is VerifySdkException)
        }
    }

    @Test
    fun sealedClass_shouldBeExhaustive() {
        // Given
        val exception: MFAServiceException = MFAServiceException.InvalidSigningHash()

        // When/Then - Verify sealed class behavior
        when (exception) {
            is MFAServiceException.InvalidSigningHash -> assertTrue(true)
            is MFAServiceException.InvalidPendingTransaction -> assertTrue(true)
            is MFAServiceException.SerializationFailed -> assertTrue(true)
            is MFAServiceException.InvalidDataResponse -> assertTrue(true)
            is MFAServiceException.DecodingFailed -> assertTrue(true)
            is MFAServiceException.UnableToCreateTransaction -> assertTrue(true)
            is MFAServiceException.General -> assertTrue(true)
        }
    }

    @Test
    fun exceptions_canBeThrown() {
        // Given
        var caughtException: MFAServiceException? = null

        // When
        try {
            throw MFAServiceException.SerializationFailed()
        } catch (e: MFAServiceException) {
            caughtException = e
        }

        // Then
        assertNotNull(caughtException)
        assertTrue(caughtException is MFAServiceException.SerializationFailed)
    }

    @Test
    fun exceptions_withNestedCause_shouldPreserveCauseChain() {
        // Given
        val rootCause = RuntimeException("Root")
        val intermediateCause = IllegalArgumentException("Intermediate", rootCause)

        // When
        val exception = MFAServiceException.DecodingFailed(intermediateCause)

        // Then
        assertEquals(intermediateCause, exception.cause)
        assertEquals(rootCause, exception.cause?.cause)
    }

    @Test
    fun exceptions_canBeCaughtAsVerifySdkException() {
        // Given
        var caughtException: VerifySdkException? = null

        // When
        try {
            throw MFAServiceException.InvalidDataResponse()
        } catch (e: VerifySdkException) {
            caughtException = e
        }

        // Then
        assertNotNull(caughtException)
        assertTrue(caughtException is MFAServiceException.InvalidDataResponse)
    }
}
