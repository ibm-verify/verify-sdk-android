/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.cloud

import com.ibm.security.verifysdk.mfa.EnrollableFactor
import com.ibm.security.verifysdk.mfa.EnrollableType
import java.net.URL

internal data class CloudTOTPEnrollableFactor(
    override val uri: URL,
    override val type: EnrollableType = EnrollableType.TOTP,
    override val enabled: Boolean,
    val id: String,
    val algorithm: String,
    val secret: String,
    val digits: Int,
    val period: Int
) : EnrollableFactor