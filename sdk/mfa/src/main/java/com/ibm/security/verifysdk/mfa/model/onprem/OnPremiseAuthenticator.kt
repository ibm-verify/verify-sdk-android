/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
@file:UseSerializers(URLSerializer::class)
package com.ibm.security.verifysdk.mfa.model.onprem

import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.serializer.URLSerializer
import com.ibm.security.verifysdk.mfa.BiometricFactorInfo
import com.ibm.security.verifysdk.mfa.MFAAuthenticatorDescriptor
import com.ibm.security.verifysdk.mfa.UserPresenceFactorInfo
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import java.net.URL


@OptIn(InternalSerializationApi::class)
@Serializable
class OnPremiseAuthenticator (
    override val refreshUri: URL,
    override val transactionUri: URL,
    override var theme: Map<String, String>,
    override var token: TokenInfo,
    override val id: String,
    override val serviceName: String,
    override var accountName: String,
    override val biometric: BiometricFactorInfo? = null,
    override val userPresence: UserPresenceFactorInfo? = null,
    val qrLoginUri: URL?,
    val ignoreSSLCertificate: Boolean = false,
    val clientId: String
) : MFAAuthenticatorDescriptor