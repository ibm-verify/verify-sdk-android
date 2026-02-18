/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

@file:UseSerializers(URLSerializer::class)
package com.ibm.security.verifysdk.mfa.model.onprem

import com.ibm.security.verifysdk.core.serializer.URLSerializer
import com.ibm.security.verifysdk.mfa.EnrollableFactor
import com.ibm.security.verifysdk.mfa.EnrollableType
import com.ibm.security.verifysdk.mfa.HashAlgorithmType
import com.ibm.security.verifysdk.mfa.SignatureEnrollableFactor
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import java.net.URL

@Serializable
internal data class Metadata(
    val registrationUri: URL,
    val transactionUri: URL,
    val signatureUri: URL,
    val totpUri: URL,
    val qrloginUri: URL,
    val serviceName: String,
    val availableFactors: ArrayList<EnrollableFactor>,
    val theme: Map<String, String>,
    val features: ArrayList<String>
)


@Serializable
internal data class DetailsData @OptIn(ExperimentalSerializationApi::class) constructor(
    @SerialName("authntrxn_endpoint")
    val authntrxnEndpoint: URL,
    @SerialName("metadata")
    val metadataService: MetadataService,
    @SerialName("discovery_mechanisms")
    val discoveryMechanisms: ArrayList<DiscoveredMechanisms> = arrayListOf(),
    @SerialName("enrollment_endpoint")
    val enrollmentEndpoint: URL,
    @SerialName("qrlogin_endpoint")
    var qrloginEndpoint: URL,
    @SerialName("hotp_shared_secret_endpoint")
    val hotpSharedSecretEndpoint: URL,
    @SerialName("totp_shared_secret_endpoint")
    val totpSharedSecretEndpoint: URL,
    @SerialName("version")
    val version: String,
    @SerialName("token_endpoint")
    val tokenEndpoint: URL,
    val theme: Map<String, String>? = null
) {

    val serviceName: String = metadataService.serviceName ?: enrollmentEndpoint.host
    var availableFactors: ArrayList<EnrollableFactor> = ArrayList()

    init {
        if (discoveryMechanisms.contains(DiscoveredMechanisms.USERPRESENCE)) {
            availableFactors.add(
                SignatureEnrollableFactor(
                    uri = enrollmentEndpoint,
                    type = EnrollableType.USER_PRESENCE,
                    enabled = true,
                    algorithm = HashAlgorithmType.SHA512.toString()
                )
            )
        }

        if (discoveryMechanisms.contains(DiscoveredMechanisms.FINGERPRINT)) {
            availableFactors.add(
                SignatureEnrollableFactor(
                    uri = enrollmentEndpoint,
                    type = EnrollableType.FINGERPRINT,
                    enabled = true,
                    algorithm = HashAlgorithmType.SHA512.toString()
                )
            )
        }

        if (discoveryMechanisms.contains(DiscoveredMechanisms.TOTP)) {
            availableFactors.add(
                OnPremiseTOTPEnrollableFactor(
                    uri = totpSharedSecretEndpoint,
                    enabled = true
                )
            )
        }
    }
}

@Serializable
internal enum class DiscoveredMechanisms(val value: String) {
    @SerialName("urn:ibm:security:authentication:asf:mechanism:totp")
    TOTP("urn:ibm:security:authentication:asf:mechanism:totp"),
    @SerialName("urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:fingerprint")
    FINGERPRINT("urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:fingerprint"),
    @SerialName("urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence")
    USERPRESENCE("urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence")
}

@Serializable
@OptIn(ExperimentalSerializationApi::class)
internal data class MetadataService (
    @SerialName("service_name" )
    val serviceName: String?
)