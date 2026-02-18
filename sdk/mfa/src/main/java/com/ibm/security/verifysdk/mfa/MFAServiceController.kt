/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.mfa.api.CloudAuthenticatorService
import com.ibm.security.verifysdk.mfa.api.OnPremiseAuthenticatorService
import com.ibm.security.verifysdk.mfa.model.cloud.CloudAuthenticator
import com.ibm.security.verifysdk.mfa.model.onprem.OnPremiseAuthenticator

/**
 * An instance you use to instantiate an [MFAServiceDescriptor] to perform transaction,
 * login and token refresh operations.
 *
 * The [MFAServiceController] is responsible for creating the appropriate service implementation
 * based on the type of authenticator (Cloud or On-Premise). It provides access to transaction
 * verification, passwordless login, and token refresh capabilities.
 *
 * ## Usage Example
 * ```kotlin
 * // Assume you have a registered authenticator
 * val authenticator: MFAAuthenticatorDescriptor = // ... loaded from storage
 *
 * // Create the service controller
 * val controller = MFAServiceController(authenticator)
 *
 * // Initiate the service
 * val service = controller.initiate()
 *
 * // Check for pending transactions
 * service.nextTransaction().onSuccess { (transaction, count) ->
 *     transaction?.let {
 *         println("Transaction message: ${it.message}")
 *         println("Pending transactions: $count")
 *
 *         // Complete the transaction using biometric or user presence
 *         authenticator.biometric?.let { biometric ->
 *             service.completeTransaction(
 *                 userAction = UserAction.VERIFY,
 *                 factorType = FactorType.Biometric(biometric)
 *             ).onSuccess {
 *                 println("Transaction completed successfully")
 *             }
 *         }
 *     }
 * }
 *
 * // Perform passwordless login (if QR code provides login endpoint)
 * val loginUri = URL("https://example.com/qrlogin")
 * val code = "authorization-code-from-qr"
 * service.login(loginUri, code).onSuccess {
 *     println("Login successful")
 * }
 *
 * // Refresh the OAuth token
 * service.refreshToken(
 *     refreshToken = authenticator.token.refreshToken,
 *     accountName = authenticator.accountName,
 *     pushToken = "new-push-token",
 *     additionalData = null
 * ).onSuccess { newToken ->
 *     println("Token refreshed: ${newToken.accessToken}")
 * }
 * ```
 *
 * @property authenticator The multi-factor authenticator used to create the service.
 *                        Must be either [CloudAuthenticator] or [OnPremiseAuthenticator].
 *
 * @constructor Creates an instance with an [MFAAuthenticatorDescriptor].
 * @param authenticator The multi-factor authenticator. Must be either [CloudAuthenticator]
 *                     or [OnPremiseAuthenticator].
 *
 * @throws IllegalArgumentException if the authenticator is not a [CloudAuthenticator]
 *                                 or [OnPremiseAuthenticator].
 *
 * @see MFAServiceDescriptor
 * @see CloudAuthenticator
 * @see OnPremiseAuthenticator
 * @see CloudAuthenticatorService
 * @see OnPremiseAuthenticatorService
 */
class MFAServiceController(private val authenticator: MFAAuthenticatorDescriptor) {

    init {
        require(authenticator is OnPremiseAuthenticator || authenticator is CloudAuthenticator) {
            "Invalid authenticator type. Only OnPremiseAuthenticator or CloudAuthenticator is allowed."
        }
    }

    /**
     * Determines the service to initiate for a multi-factor authenticator.
     *
     * This method creates and returns the appropriate [MFAServiceDescriptor] implementation
     * based on the type of authenticator:
     * - For [CloudAuthenticator]: Returns a [CloudAuthenticatorService]
     * - For [OnPremiseAuthenticator]: Returns an [OnPremiseAuthenticatorService]
     *
     * The returned service can be used to:
     * - Check for pending transactions
     * - Complete transactions with user actions
     * - Perform passwordless login
     * - Refresh OAuth tokens
     *
     * ## Usage Example
     * ```kotlin
     * val controller = MFAServiceController(authenticator)
     * val service = controller.initiate()
     *
     * // Use the service for various operations
     * service.nextTransaction().onSuccess { (transaction, count) ->
     *     // Handle transaction
     * }
     * ```
     *
     * @return An [MFAServiceDescriptor] instance configured for the authenticator type.
     *         This will be either a [CloudAuthenticatorService] or [OnPremiseAuthenticatorService].
     *
     * @throws MFARegistrationException.InvalidFormat if the authenticator type is neither
     *                                           [CloudAuthenticator] nor [OnPremiseAuthenticator].
     *                                           This should never occur due to the init block validation.
     *
     * @see MFAServiceDescriptor
     * @see CloudAuthenticatorService
     * @see OnPremiseAuthenticatorService
     */
    fun initiate(): MFAServiceDescriptor {

        when (authenticator) {
            is OnPremiseAuthenticator -> return OnPremiseAuthenticatorService(
                _accessToken = authenticator.token.accessToken,
                _refreshUri = authenticator.refreshUri,
                _transactionUri = authenticator.transactionUri,
                _clientId = authenticator.clientId,
                _authenticatorId = authenticator.id,
                _ignoreSslCertificate = authenticator.ignoreSSLCertificate
            )

            is CloudAuthenticator -> return CloudAuthenticatorService(
                _accessToken = authenticator.token.accessToken,
                _refreshUri = authenticator.refreshUri,
                _transactionUri = authenticator.transactionUri,
                _authenticatorId = authenticator.id
            )

            else -> throw MFARegistrationException.InvalidFormat()
        }
    }
}
