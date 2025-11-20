/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

/**
 * The enumerated type of user actions that can be performed to complete a transaction.
 *
 * These actions represent the possible responses a user can provide when completing
 * a multi-factor authentication transaction.
 *
 * ## Usage Example
 * ```kotlin
 * val controller = MFAServiceController(authenticator)
 * val service = controller.initiate()
 *
 * // Get the next transaction
 * service.nextTransaction().onSuccess { (transaction, count) ->
 *     transaction?.let {
 *         // User approves the transaction
 *         service.completeTransaction(
 *             userAction = UserAction.VERIFY,
 *             factorType = factorType
 *         )
 *     }
 * }
 *
 * // Or user denies the transaction
 * service.completeTransaction(
 *     userAction = UserAction.DENY,
 *     signedData = ""
 * )
 * ```
 *
 * @property value The string value sent to the server representing this action.
 *
 * @see MFAServiceDescriptor.completeTransaction
 */
enum class UserAction(val value: String) {
    /**
     * The user has denied or rejected the transaction.
     *
     * Use this action when the user explicitly rejects the authentication request.
     * No signature data is required for this action.
     */
    DENY("USER_DENIED"),

    /**
     * The user has denied the transaction and marked it as fraudulent.
     *
     * Use this action when the user not only rejects the authentication request
     * but also wants to report it as a fraudulent or suspicious attempt.
     * No signature data is required for this action.
     */
    MARK_AS_FRAUD("USER_FRAUDULENT"),

    /**
     * The user is attempting to verify the transaction.
     *
     * Use this action when the user approves the authentication request.
     * The request must also include signed data generated using the private key
     * associated with the enrolled factor.
     */
    VERIFY("VERIFY_ATTEMPT"),

    /**
     * The user was unable to verify the transaction due to a failed device biometry attempt.
     *
     * Use this action when biometric authentication (fingerprint or face recognition)
     * fails and the user cannot complete the verification.
     * No signature data is required for this action.
     */
    BIOMETRY_FAILED("BIOMETRY_FAILED")
}
