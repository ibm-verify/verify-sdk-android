/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.onprem

import com.ibm.security.verifysdk.core.serializer.InstantIsoSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@Serializable
internal data class TransactionResult(
    @SerialName("transactionsPending")
    var transactions: List<TransactionInfo> = emptyList(),
    @SerialName("attributesPending")
    var attributes: List<AttributeInfo> = emptyList()
) {

    @Serializable
    data class AttributeInfo(
        val dataType: String,
        val values: List<String>,
        val uri: String,
        val transactionId: String
    )

    @OptIn(ExperimentalTime::class)
    @Serializable
    data class TransactionInfo(
        @Serializable(with = InstantIsoSerializer::class)
        val creationTime: Instant,
        val requestUrl: String,
        val transactionId: String,
        @SerialName("authnPolicyURI")
        val authnPolicyUri: String
    )

    object TransactionResultSerializer : JsonTransformingSerializer<TransactionResult>(serializer()) {
        override fun transformDeserialize(element: JsonElement): JsonElement {
            val transactionsElement = element.jsonObject["urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction"]
            val attributesPending = transactionsElement?.jsonObject?.get("attributesPending")
            val transactionsPending = transactionsElement?.jsonObject?.get("transactionsPending")

            return buildJsonObject {
                if (attributesPending != null) put("attributesPending", attributesPending)
                if (transactionsPending != null) put("transactionsPending", transactionsPending)
            }
        }
    }
}

