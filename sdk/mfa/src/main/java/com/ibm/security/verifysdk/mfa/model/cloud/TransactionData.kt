/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.cloud

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Represents the transaction data payload from Cloud MFA transactions.
 *
 * This data class provides type-safe access to transaction information that was previously
 * parsed using org.json.JSONObject. All fields are nullable to handle missing or optional
 * data gracefully.
 *
 * ## Usage Example
 * ```kotlin
 * val transactionData = DefaultJson.decodeFromString<TransactionData>(jsonString)
 * val message = transactionData.message ?: "Default message"
 * val ipAddress = transactionData.originIpAddress
 * ```
 *
 * @property message The transaction message to display to the user
 * @property originIpAddress The IP address where the transaction originated
 * @property originUserAgent The user agent string from the originating client
 * @property additionalData List of additional key-value pairs with transaction metadata
 *
 * @see AdditionalDataItem
 * @see com.ibm.security.verifysdk.mfa.api.CloudAuthenticatorService
 */
@Serializable
internal data class TransactionData(
    @SerialName("message")
    val message: String? = null,
    
    @SerialName("originIpAddress")
    val originIpAddress: String? = null,
    
    @SerialName("originUserAgent")
    val originUserAgent: String? = null,
    
    @SerialName("additionalData")
    val additionalData: List<AdditionalDataItem>? = null
)

/**
 * Represents an additional data item in the transaction payload.
 *
 * Additional data items are key-value pairs that provide extra context about the transaction.
 * Some well-known names have special handling:
 * - `type`: The type of transaction (e.g., "Login", "Payment")
 * - `originLocation`: Geographic location where transaction originated
 * - `imageURL`: URL to an image associated with the transaction
 * - `denyReasonEnabled`: Whether the user can provide a reason for denying
 *
 * Other names are treated as custom data and preserved in the transaction attributes.
 *
 * ## Usage Example
 * ```kotlin
 * val item = AdditionalDataItem(name = "type", value = "Login")
 * when (item.name) {
 *     "type" -> handleTransactionType(item.value)
 *     "originLocation" -> handleLocation(item.value)
 *     else -> handleCustomData(item.name, item.value)
 * }
 * ```
 *
 * @property name The name/key of the data item
 * @property value The value of the data item
 *
 * @see TransactionData
 */
@Serializable
internal data class AdditionalDataItem(
    @SerialName("name")
    val name: String,
    
    @SerialName("value")
    val value: String
)

