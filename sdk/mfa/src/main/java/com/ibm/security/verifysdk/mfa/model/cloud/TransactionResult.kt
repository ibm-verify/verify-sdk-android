/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.cloud

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@Serializable
internal data class TransactionResult(
    @SerialName("total") var count: Int = 0,
    @SerialName("verifications") var verifications: List<VerificationInfo>? = null
) {
    /**
     * Contains verification information for a Cloud MFA transaction.
     *
     * @property id The unique identifier for this verification
     * @property creationTime The time when this verification was created
     * @property expiryTime The time when this verification expires. May be null if not provided
     *                      in the API response (depends on filter parameters)
     * @property correlationEnabled Indicates whether correlation is enabled for this transaction.
     *                              Defaults to false if not present in the response
     * @property correlationValue The correlation value for the transaction, typically a 2-digit
     *                           number. May be null if not provided in the response
     * @property transactionInfo JSON string containing transaction details and context
     * @property methodInfo List of authentication methods available for this verification
     */
    @OptIn(ExperimentalTime::class)
    @Serializable
    data class VerificationInfo(
        val id: String,
        val creationTime: Instant,
        val expiryTime: Instant? = null,
        val correlationEnabled: Boolean = false,
        val correlationValue: String? = null,
        @SerialName("transactionData") val transactionInfo: String,
        @SerialName("authenticationMethods") val methodInfo: List<MethodInfo>
    ) {
        @Serializable
        data class MethodInfo(
            val id: String,
            val methodType: String,
            val subType: String
        )
    }
}