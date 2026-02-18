/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import com.ibm.security.verifysdk.authentication.model.TokenInfo
import java.net.URL

interface MFAAuthenticatorDescriptor : AuthenticatorDescriptor {

    val refreshUri : URL
    val transactionUri : URL
    var theme : Map<String, String>
    var token : TokenInfo
    
    /**
     * The biometric factor information for this authenticator, if available.
     */
    val biometric: BiometricFactorInfo?
    
    /**
     * The user presence factor information for this authenticator, if available.
     */
    val userPresence: UserPresenceFactorInfo?
}