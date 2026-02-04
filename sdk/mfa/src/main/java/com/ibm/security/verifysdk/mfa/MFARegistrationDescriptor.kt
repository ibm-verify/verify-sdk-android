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

    val countOfAvailableEnrollments: Int

    @Throws
    fun nextEnrollment(): EnrollableSignature?

    @Throws
    suspend fun enroll(httpClient: HttpClient = NetworkHelper.getInstance)

    @Throws
    suspend fun enroll(keyName: String, publicKey: String, signedData: String, httpClient: HttpClient = NetworkHelper.getInstance)

    @Throws
    suspend fun finalize(httpClient: HttpClient = NetworkHelper.getInstance): Result<MFAAuthenticatorDescriptor>
}

/**
 * Type alias representing a JSON string containing registration initiation data.
 */
typealias RegistrationInitiation = String