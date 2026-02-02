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
    const val KEY_FCM_TOKEN = "fcm_token"
    const val TYPE_CLOUD = "cloud"
    const val TYPE_ONPREM = "onprem"
    
    // Intent extra keys for push notification data
    const val EXTRA_TRANSACTION_ID = "extra_transaction_id"
    const val EXTRA_AUTHENTICATOR_ID = "extra_authenticator_id"
    const val EXTRA_HANDLE_TRANSACTION = "extra_handle_transaction"
}
