/*
 * Copyright contributors to the IBM Verify Digital Credentials SDK for Android project
 */

package com.ibm.security.verifysdk.dc.model

import com.ibm.security.verifysdk.dc.model.CredentialFormat.INDY
import com.ibm.security.verifysdk.dc.model.CredentialFormat.JSON_LD
import com.ibm.security.verifysdk.dc.model.CredentialFormat.MDOC
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonNames

/**
 * Represents the different formats for credentials.
 *
 * This enum class defines the various formats in which credentials can be represented, such as
 * Indy, JSON-LD, and MSO MDoc. Each format has a corresponding serial name used for serialization
 * and deserialization.
 *
 * @property INDY The Indy credential format.
 * @property JSON_LD The JSON-LD credential format.
 * @property MDOC The MSO MDoc credential format.
 *
 * @since 3.0.7
 */
@Serializable
enum class CredentialFormat {
    @SerialName("indy")
    INDY,

    @SerialName("jsonld")
    JSON_LD,

    @OptIn(ExperimentalSerializationApi::class)
    @JsonNames("mso_mdoc", "mso_mdoc_detail", "mso_mdoc_preview")
    MDOC,

    @OptIn(ExperimentalSerializationApi::class)
    @JsonNames("dc+sd-jwt")
    SDJWT;

    companion object {
        val CredentialFormat.serialName: String
            get() = when (this) {
                INDY -> "indy"
                JSON_LD -> "jsonld"
                MDOC -> "mso_mdoc"
                SDJWT -> "dc+sd-jwt"
            }

        /**
         * Creates a [CredentialFormat] instance from its serial name.
         *
         * @param name The serial name to create a [CredentialFormat] instance from.
         * @return The corresponding [CredentialFormat] instance.
         * @throws IllegalArgumentException If the provided serial name is not recognized.
         */
        fun fromSerialName(name: String): CredentialFormat {
            return entries.firstOrNull { it.serialName == name }
                ?: throw IllegalArgumentException("Unknown format: $name")
        }
    }
}