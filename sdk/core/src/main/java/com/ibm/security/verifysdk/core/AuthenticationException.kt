/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.core

import io.ktor.http.HttpStatusCode

/**
 * This exception occurs when authentication has failed.
 *
 * @param code The HTTP status code of the authentication failure.
 * @param id The error identifier.
 * @param description A human-readable description of the error.
 * @param cause The underlying cause of the exception, if any.
 *
 * @since 3.0.0
 */
class AuthenticationException(
    val code: HttpStatusCode,
    id: String,
    description: String,
    cause: Throwable? = null
) : VerifySdkException(Error(id, description), cause)
