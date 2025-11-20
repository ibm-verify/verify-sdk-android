/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.mfa.demoapp

/**
 * Constants used throughout the MFA Demo application
 */
object Constants {
    // Factor type strings
    const val FACTOR_TYPE_FACE = "face"
    const val FACTOR_TYPE_FINGERPRINT = "fingerprint"
    
    // SharedPreferences keys
    const val PREFS_NAME = "mfa_demo_prefs"
    const val KEY_AUTHENTICATOR = "authenticator"
    const val KEY_AUTHENTICATOR_TYPE = "authenticator_type"
    const val TYPE_CLOUD = "cloud"
    const val TYPE_ONPREM = "onprem"
}
