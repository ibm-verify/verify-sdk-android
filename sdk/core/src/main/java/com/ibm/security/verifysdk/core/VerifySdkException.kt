/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.core

import kotlinx.serialization.Serializable

/**
 * A data class representing a standardized error response.
 *
 * @property id A unique identifier for the error.
 * @property description A human-readable description of the error.
 */
@Serializable
data class Error(val id: String, val description: String)

/**
 * VerifySdkException is a generic exception that can be thrown when working with the Verify SDK.
 *
 * @param error The structured error information.
 * @param cause The underlying cause of the exception, if any.
 *
 * @since 3.0.0
 */
@Suppress("MemberVisibilityCanBePrivate")
open class VerifySdkException(
    val error: Error,
    override val cause: Throwable? = null
) : Exception(error.description, cause) {

    /**
     * Returns a string representation of the exception object.
     */
    override fun toString(): String {
        val causeMessage = cause?.let { " | Cause: ${it.message}" } ?: ""
        val className = this::class.simpleName ?: "VerifySdkException"
        return "$className(error=${error.id}, description='${error.description}'$causeMessage)"
    }
}