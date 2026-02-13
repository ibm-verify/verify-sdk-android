/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.helper.NetworkHelper
import io.ktor.client.HttpClient

interface MFARegistrationDescriptor<out Authenticator : MFAAuthenticatorDescriptor> {

    var pushToken: String
    var accountName: String
    var authenticationRequired: Boolean
    var invalidatedByBiometricEnrollment: Boolean

    val canEnrollUserPresence: Boolean
    val canEnrollBiomtric: Boolean
    val countOfAvailableEnrollments: Int

    @Throws
    suspend fun enrollBiometric(httpClient: HttpClient = NetworkHelper.getInstance)

    @Throws
    suspend fun enrollUserPresence(httpClient: HttpClient = NetworkHelper.getInstance)

    @Throws
    suspend fun finalize(httpClient: HttpClient = NetworkHelper.getInstance): Result<MFAAuthenticatorDescriptor>
}

/**
 * Type alias representing a JSON string containing registration initiation data.
 */
typealias RegistrationInitiation = String