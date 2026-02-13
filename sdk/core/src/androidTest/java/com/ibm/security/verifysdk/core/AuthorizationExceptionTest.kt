/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.core

import io.ktor.http.HttpStatusCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

internal class AuthorizationExceptionTest {

    @Test
    fun constructor_withoutCause_shouldReturnObject() {
        val exception = AuthorizationException(
            HttpStatusCode.Forbidden,
            "access_denied",
            "Access to the resource is forbidden"
        )

        assertEquals("access_denied", exception.error.id)
        assertEquals("Access to the resource is forbidden", exception.error.description)
        assertEquals(HttpStatusCode.Forbidden, exception.code)
        assertNull(exception.cause)
    }

    @Test
    fun constructor_withCause_shouldReturnObject() {
        val cause = IllegalStateException("Invalid state")
        val exception = AuthorizationException(
            HttpStatusCode.Unauthorized,
            "unauthorized",
            "User is not authorized",
            cause
        )

        assertEquals("unauthorized", exception.error.id)
        assertEquals("User is not authorized", exception.error.description)
        assertEquals(HttpStatusCode.Unauthorized, exception.code)
        assertNotNull(exception.cause)
        assertEquals(cause, exception.cause)
    }

    @Test
    fun constructor_withDifferentStatusCodes_shouldReturnCorrectCode() {
        val exception401 = AuthorizationException(
            HttpStatusCode.Unauthorized,
            "unauthorized",
            "Unauthorized access"
        )
        assertEquals(HttpStatusCode.Unauthorized, exception401.code)

        val exception403 = AuthorizationException(
            HttpStatusCode.Forbidden,
            "forbidden",
            "Forbidden access"
        )
        assertEquals(HttpStatusCode.Forbidden, exception403.code)

        val exception500 = AuthorizationException(
            HttpStatusCode.InternalServerError,
            "server_error",
            "Internal server error"
        )
        assertEquals(HttpStatusCode.InternalServerError, exception500.code)
    }

    @Test
    fun constructor_withEmptyStrings_shouldReturnObject() {
        val exception = AuthorizationException(
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
        val exception = AuthorizationException(
            HttpStatusCode.Forbidden,
            "error_id_with_special_chars!@#",
            "Description with special chars: <>&\"'"
        )

        assertEquals("error_id_with_special_chars!@#", exception.error.id)
        assertEquals("Description with special chars: <>&\"'", exception.error.description)
        assertEquals(HttpStatusCode.Forbidden, exception.code)
    }
}