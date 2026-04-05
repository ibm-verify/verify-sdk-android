/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.onprem

import kotlinx.serialization.Serializable
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

/**
 * Contains verification information for an OnPremise MFA transaction.
 *
 * @property mechanism The authentication mechanism URI
 * @property location The location URI for posting the verification response
 * @property type The type of verification
 * @property serverChallenge The challenge string from the server (mutable for signing operations)
 * @property keyHandles List of key handles associated with this verification
 * @property expiryTime The time when this verification expires. If not provided in the response,
 *                      it will be calculated as creationTime + 300 seconds
 */
@OptIn(ExperimentalTime::class)
@Serializable
data class VerificationInfo(
    val mechanism: String,
    val location: String,
    val type: String,
    var serverChallenge: String,
    val keyHandles: List<String>,
    val expiryTime: Instant? = null
)