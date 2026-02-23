/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.helper.NetworkHelper
import io.ktor.client.HttpClient

/**
 * Defines the contract for multi-factor authentication registration providers.
 *
 * This interface provides the core functionality for enrolling authentication factors
 * and finalizing the registration process. Implementations handle the specific details
 * of communicating with either cloud-based or on-premise authentication services.
 *
 * @param Authenticator The type of authenticator descriptor returned upon successful registration.
 *
 * @see CloudRegistrationProvider
 * @see OnPremiseRegistrationProvider
 */
interface MFARegistrationDescriptor<out Authenticator : MFAAuthenticatorDescriptor> {

    /**
     * The push notification token for the device.
     *
     * This token is typically obtained from Firebase Cloud Messaging (FCM) and is used
     * to send push notifications for transaction verification and other MFA operations.
     */
    var pushToken: String

    /**
     * The account name associated with this registration.
     *
     * This is typically the user's display name or identifier that will be shown
     * in the authenticator application.
     */
    var accountName: String

    /**
     * Indicates whether user authentication is required for biometric operations.
     *
     * When `true`, the user must authenticate (e.g., via PIN, pattern, or password)
     * before biometric operations can be performed.
     */
    var authenticationRequired: Boolean

    /**
     * Indicates whether biometric keys should be invalidated when new biometrics are enrolled.
     *
     * When `true`, adding new fingerprints or face data will invalidate existing
     * biometric keys, requiring re-enrollment of the MFA factor.
     */
    var invalidatedByBiometricEnrollment: Boolean

    /**
     * Indicates whether user presence verification can be enrolled.
     *
     * User presence verification typically requires the user to confirm their presence
     * through a simple action like tapping a button, without requiring biometric authentication.
     *
     * @return `true` if user presence enrollment is available, `false` otherwise.
     */
    val canEnrollUserPresence: Boolean

    /**
     * Indicates whether biometric verification can be enrolled.
     *
     * Biometric verification uses fingerprint, face recognition, or other biometric
     * methods to authenticate the user.
     *
     * @return `true` if biometric enrollment is available, `false` otherwise.
     */
    val canEnrollBiomtric: Boolean

    /**
     * The number of authentication factors available for enrollment.
     *
     * This count includes all factors that can still be enrolled, such as TOTP,
     * user presence, and biometric verification.
     *
     * @return The count of available enrollments.
     */
    val countOfAvailableEnrollments: Int

    /**
     * Enrolls biometric verification as an authentication factor.
     *
     * This method registers the device's biometric capabilities (fingerprint, face recognition)
     * as an authentication factor. The biometric data is stored securely on the device and
     * never transmitted to the server.
     *
     * @param httpClient Optional HTTP client instance for making network requests.
     *                   Defaults to [NetworkHelper.getInstance].
     *
     * @throws MFARegistrationException if enrollment fails due to network errors,
     *         invalid state, or server rejection.
     * @throws BiometricAuthenticationException if biometric hardware is not available
     *         or biometric enrollment fails.
     */
    @Throws
    suspend fun enrollBiometric(httpClient: HttpClient = NetworkHelper.getInstance)

    /**
     * Enrolls user presence verification as an authentication factor.
     *
     * This method registers a simpler form of verification that confirms the user's
     * presence without requiring biometric authentication. This is typically used
     * for lower-security scenarios or as a fallback when biometrics are unavailable.
     *
     * @param httpClient Optional HTTP client instance for making network requests.
     *                   Defaults to [NetworkHelper.getInstance].
     *
     * @throws MFARegistrationException if enrollment fails due to network errors,
     *         invalid state, or server rejection.
     */
    @Throws
    suspend fun enrollUserPresence(httpClient: HttpClient = NetworkHelper.getInstance)

    /**
     * Finalizes the registration process and returns the registered authenticator.
     *
     * This method completes the registration flow by submitting all enrolled factors
     * to the authentication service and retrieving the final authenticator descriptor.
     * After successful finalization, the authenticator can be used for authentication
     * operations.
     *
     * @param httpClient Optional HTTP client instance for making network requests.
     *                   Defaults to [NetworkHelper.getInstance].
     *
     * @return A [Result] containing either:
     *         - Success: An [MFAAuthenticatorDescriptor] representing the registered authenticator
     *         - Failure: An [MFARegistrationException] indicating why finalization failed
     *
     * @throws MFARegistrationException if finalization fails due to network errors,
     *         incomplete enrollment, or server rejection.
     */
    @Throws
    suspend fun finalize(httpClient: HttpClient = NetworkHelper.getInstance): Result<MFAAuthenticatorDescriptor>
}

/**
 * Type alias representing a JSON string containing registration initiation data.
 */
typealias RegistrationInitiation = String