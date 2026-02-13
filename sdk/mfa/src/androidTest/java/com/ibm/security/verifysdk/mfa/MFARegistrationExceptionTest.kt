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
class MFARegistrationExceptionTest {

    @Test
    fun failedToParse_withoutCause_shouldCreateException() {
        // When
        val exception = MFARegistrationException.FailedToParse()

        // Then
        assertNotNull(exception)
        assertTrue(exception is MFARegistrationException)
        assertTrue(exception is VerifySdkException)
        assertNull(exception.cause)
        assertEquals("failed_to_parse", exception.error.id)
        assertEquals("Failed to parse JSON value.", exception.error.description)
    }

    @Test
    fun failedToParse_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = IllegalArgumentException("Invalid JSON")

        // When
        val exception = MFARegistrationException.FailedToParse(cause)

        // Then
        assertEquals(cause, exception.cause)
        assertEquals("failed_to_parse", exception.error.id)
    }

    @Test
    fun invalidFormat_withoutCause_shouldCreateException() {
        // When
        val exception = MFARegistrationException.InvalidFormat()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("invalid_format", exception.error.id)
        assertEquals("Invalid JSON format to create an MFARegistrationDescriptor.", exception.error.description)
    }

    @Test
    fun invalidFormat_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = RuntimeException("Format error")

        // When
        val exception = MFARegistrationException.InvalidFormat(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun noEnrollableFactors_withoutCause_shouldCreateException() {
        // When
        val exception = MFARegistrationException.NoEnrollableFactors()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("no_enrollable_factors", exception.error.id)
        assertEquals("No enrollable factors available for enrollment.", exception.error.description)
    }

    @Test
    fun noEnrollableFactors_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = IllegalStateException("No factors")

        // When
        val exception = MFARegistrationException.NoEnrollableFactors(EnrollableType.USER_PRESENCE, cause)

        // Then
        assertTrue(exception.message?.contains(EnrollableType.USER_PRESENCE.toString()) ?: false)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun enrollmentFailed_withoutCause_shouldCreateException() {
        // When
        val exception = MFARegistrationException.EnrollmentFailed()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("enrollment_failed", exception.error.id)
        assertEquals("Factor enrollment failed.", exception.error.description)
    }

    @Test
    fun enrollmentFailed_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = Exception("Enrollment error")

        // When
        val exception = MFARegistrationException.EnrollmentFailed(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun dataInitializationFailed_withoutCause_shouldCreateException() {
        // When
        val exception = MFARegistrationException.DataInitializationFailed()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("data_initialization_failed", exception.error.id)
        assertEquals("Initialization failed.", exception.error.description)
    }

    @Test
    fun dataInitializationFailed_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = NullPointerException("Null data")

        // When
        val exception = MFARegistrationException.DataInitializationFailed(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun missingAuthenticatorIdentifier_withoutCause_shouldCreateException() {
        // When
        val exception = MFARegistrationException.MissingAuthenticatorIdentifier()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("missing_authenticator_identifier", exception.error.id)
        assertEquals("Authenticator identifier missing from OAuth token.", exception.error.description)
    }

    @Test
    fun missingAuthenticatorIdentifier_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = IllegalArgumentException("Missing ID")

        // When
        val exception = MFARegistrationException.MissingAuthenticatorIdentifier(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun invalidRegistrationData_withoutCause_shouldCreateException() {
        // When
        val exception = MFARegistrationException.InvalidRegistrationData()

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("invalid_registration_data", exception.error.id)
        assertEquals("Invalid multi-factor registration data.", exception.error.description)
    }

    @Test
    fun invalidRegistrationData_withCause_shouldCreateExceptionWithCause() {
        // Given
        val cause = IllegalStateException("Invalid data")

        // When
        val exception = MFARegistrationException.InvalidRegistrationData(cause)

        // Then
        assertEquals(cause, exception.cause)
    }

    @Test
    fun general_withDescription_shouldCreateException() {
        // Given
        val description = "Custom error description"

        // When
        val exception = MFARegistrationException.General(description)

        // Then
        assertNotNull(exception)
        assertNull(exception.cause)
        assertEquals("general_registration_error", exception.error.id)
        assertEquals(description, exception.error.description)
    }

    @Test
    fun general_withDescriptionAndCause_shouldCreateExceptionWithCause() {
        // Given
        val description = "Custom error with cause"
        val cause = RuntimeException("Root cause")

        // When
        val exception = MFARegistrationException.General(description, cause)

        // Then
        assertEquals(cause, exception.cause)
        assertEquals(description, exception.error.description)
    }

    @Test
    fun allExceptions_canBeCaughtAsMFARegistrationException() {
        // Given
        val exceptions = listOf(
            MFARegistrationException.FailedToParse(),
            MFARegistrationException.InvalidFormat(),
            MFARegistrationException.NoEnrollableFactors(),
            MFARegistrationException.EnrollmentFailed(),
            MFARegistrationException.DataInitializationFailed(),
            MFARegistrationException.MissingAuthenticatorIdentifier(),
            MFARegistrationException.InvalidRegistrationData(),
            MFARegistrationException.General("Test")
        )

        // When/Then
        for (exception in exceptions) {
            assertTrue(exception is MFARegistrationException)
            assertTrue(exception is VerifySdkException)
        }
    }

    @Test
    fun sealedClass_shouldBeExhaustive() {
        // Given
        val exception: MFARegistrationException = MFARegistrationException.FailedToParse()

        // When/Then - Verify sealed class behavior
        // If any subtype is missing, this test will fail to compile.
        when (exception) {
            is MFARegistrationException.FailedToParse -> assertTrue(true)
            is MFARegistrationException.InvalidFormat -> assertTrue(true)
            is MFARegistrationException.NoEnrollableFactors -> assertTrue(true)
            is MFARegistrationException.EnrollmentFailed -> assertTrue(true)
            is MFARegistrationException.DataInitializationFailed -> assertTrue(true)
            is MFARegistrationException.MissingAuthenticatorIdentifier -> assertTrue(true)
            is MFARegistrationException.InvalidRegistrationData -> assertTrue(true)
            is MFARegistrationException.InvalidAlgorithm -> assertTrue(true)
            is MFARegistrationException.SignatureMethodNotEnabled -> assertTrue(true)
            is MFARegistrationException.General -> assertTrue(true)
            // No else branch on purpose
        }
    }

    @Test
    fun exceptions_canBeThrown() {
        // Given
        var caughtException: MFARegistrationException? = null

        // When
        try {
            throw MFARegistrationException.EnrollmentFailed()
        } catch (e: MFARegistrationException) {
            caughtException = e
        }

        // Then
        assertNotNull(caughtException)
        assertTrue(caughtException is MFARegistrationException.EnrollmentFailed)
    }

    @Test
    fun exceptions_withNestedCause_shouldPreserveCauseChain() {
        // Given
        val rootCause = RuntimeException("Root")
        val intermediateCause = IllegalArgumentException("Intermediate", rootCause)

        // When
        val exception = MFARegistrationException.FailedToParse(intermediateCause)

        // Then
        assertEquals(intermediateCause, exception.cause)
        assertEquals(rootCause, exception.cause?.cause)
    }
}
