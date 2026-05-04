/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

enum class EnrollableType {
    TOTP,
    HOTP,
    FACE,
    FINGERPRINT,
    USER_PRESENCE;

    override fun toString(): String {
        return when (this) {
            USER_PRESENCE -> "userPresence"
            else -> name.lowercase()
        }
    }

    companion object {
        fun fromString(type: String): EnrollableType? {
            return when (type) {
                "fingerprint" -> FINGERPRINT
                "face" -> FACE
                "userPresence" -> USER_PRESENCE
                "totp" -> TOTP
                "hotp" -> HOTP
                else -> null
            }
        }
    }
}