/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.Serializable
import java.util.UUID

@InternalSerializationApi
@Serializable
sealed class FactorType {

    val id: UUID
        get() = when (this) {
            is Totp -> value.id
            is Hotp -> value.id
            is Biometric -> value.id
            is UserPresence -> value.id
        }

    val displayName: String
        get() = when (this) {
            is Totp -> value.displayName
            is Hotp -> value.displayName
            is Biometric -> value.displayName
            is UserPresence -> value.displayName
        }

    @Serializable
    data class Totp(val value: TOTPFactorInfo) : FactorType()
    @Serializable
    data class Hotp(val value: HOTPFactorInfo) : FactorType()
    @Serializable
    data class Biometric(val value: BiometricFactorInfo) : FactorType()
    @Serializable
    data class UserPresence(val value: UserPresenceFactorInfo) : FactorType()

}

@OptIn(InternalSerializationApi::class)
fun FactorType.valueType(): Factor {
    return when (this) {
        is FactorType.Totp -> this.value
        is FactorType.Hotp -> this.value
        is FactorType.Biometric -> this.value
        is FactorType.UserPresence -> this.value
    }
}