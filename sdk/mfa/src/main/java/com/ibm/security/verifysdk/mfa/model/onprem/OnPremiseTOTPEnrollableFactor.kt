/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.onprem

import com.ibm.security.verifysdk.mfa.EnrollableFactor
import com.ibm.security.verifysdk.mfa.EnrollableType
import java.net.URL

internal data class OnPremiseTOTPEnrollableFactor(
    override val uri: URL,
    override val type: EnrollableType = EnrollableType.TOTP,
    override val enabled: Boolean
) : EnrollableFactor