/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.core.serializer.URLSerializer
import kotlinx.serialization.Serializable
import java.net.URL

@Serializable
internal data class SignatureEnrollableFactor(
    @Serializable(with = URLSerializer::class)
    override val uri: URL,
    override val type: EnrollableType,
    override val enabled: Boolean,
    val algorithm: String
) : EnrollableFactor
