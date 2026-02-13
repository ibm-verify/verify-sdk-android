/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.core

import io.ktor.http.HttpStatusCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

internal class AuthenticationExceptionTest {

    @Test
    fun constructor_withoutCause_shouldReturnObject() {
        val exception = AuthenticationException(
            HttpStatusCode.InternalServerError,
            "ErrorId",
            "ErrorDescription"
        )

        assertEquals("ErrorId", exception.error.id)
        assertEquals("ErrorDescription", exception.error.description)
        assertEquals(HttpStatusCode.InternalServerError, exception.code)
        assertNull(exception.cause)
    }

    @Test
    fun constructor_withCause_shouldReturnObject() {
        val cause = RuntimeException("Network error")
        val exception = AuthenticationException(
            HttpStatusCode.Unauthorized,
            "auth_failed",
            "Authentication failed",
            cause
        )

        assertEquals("auth_failed", exception.error.id)
        assertEquals("Authentication failed", exception.error.description)
        assertEquals(HttpStatusCode.Unauthorized, exception.code)
        assertNotNull(exception.cause)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun constructor_withDifferentStatusCodes_shouldReturnCorrectCode() {
        val exception401 = AuthenticationException(
            HttpStatusCode.Unauthorized,
            "invalid_credentials",
            "Invalid username or password"
        )
        assertEquals(HttpStatusCode.Unauthorized, exception401.code)

        val exception403 = AuthenticationException(
            HttpStatusCode.Forbidden,
            "account_locked",
            "Account is locked"
        )
        assertEquals(HttpStatusCode.Forbidden, exception403.code)

        val exception500 = AuthenticationException(
            HttpStatusCode.InternalServerError,
            "server_error",
            "Internal server error"
        )
        assertEquals(HttpStatusCode.InternalServerError, exception500.code)
    }

    @Test
    fun constructor_withEmptyStrings_shouldReturnObject() {
        val exception = AuthenticationException(
            HttpStatusCode.BadRequest,
            "",
            ""
        )

        assertEquals("", exception.error.id)
        assertEquals("", exception.error.description)
        assertEquals(HttpStatusCode.BadRequest, exception.code)
    }

    @Test
    fun constructor_withSpecialCharacters_shouldReturnObject() {
        val exception = AuthenticationException(
            HttpStatusCode.Unauthorized,
            "error_id_with_special_chars!@#",
            "Description with special chars: <>&\"'"
        )

        assertEquals("error_id_with_special_chars!@#", exception.error.id)
        assertEquals("Description with special chars: <>&\"'", exception.error.description)
        assertEquals(HttpStatusCode.Unauthorized, exception.code)
    }

    @Test
    fun constructor_withLongStrings_shouldReturnObject() {
        val longId = "a".repeat(1000)
        val longDescription = "b".repeat(2000)
        val exception = AuthenticationException(
            HttpStatusCode.InternalServerError,
            longId,
            longDescription
        )

        assertEquals(longId, exception.error.id)
        assertEquals(longDescription, exception.error.description)
        assertEquals(HttpStatusCode.InternalServerError, exception.code)
    }
}