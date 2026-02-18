/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@OptIn(InternalSerializationApi::class)
@RunWith(AndroidJUnit4::class)
class FactorTypeTest {

    @Test
    fun totpFactorType_shouldCreateInstance() {
        // Given
        val totpInfo = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")

        // When
        val factorType = FactorType.Totp(totpInfo)

        // Then
        assertEquals(totpInfo, factorType.value)
        assertEquals(totpInfo.id, factorType.id)
        assertEquals(totpInfo.displayName, factorType.displayName)
    }

    @Test
    fun hotpFactorType_shouldCreateInstance() {
        // Given
        val hotpInfo = HOTPFactorInfo(secret = "ON6MJUIM4MXYVLN3")

        // When
        val factorType = FactorType.Hotp(hotpInfo)

        // Then
        assertEquals(hotpInfo, factorType.value)
        assertEquals(hotpInfo.id, factorType.id)
        assertEquals(hotpInfo.displayName, factorType.displayName)
    }

    @Test
    fun biometricFactorType_shouldCreateInstance() {
        // Given
        val biometricInfo = BiometricFactorInfo()

        // When
        val factorType = FactorType.Biometric(biometricInfo)

        // Then
        assertEquals(biometricInfo, factorType.value)
        assertEquals(biometricInfo.id, factorType.id)
        assertEquals(biometricInfo.displayName, factorType.displayName)
    }

    @Test
    fun userPresenceFactorType_shouldCreateInstance() {
        // Given
        val userPresenceInfo = UserPresenceFactorInfo()

        // When
        val factorType = FactorType.UserPresence(userPresenceInfo)

        // Then
        assertEquals(userPresenceInfo, factorType.value)
        assertEquals(userPresenceInfo.id, factorType.id)
        assertEquals(userPresenceInfo.displayName, factorType.displayName)
    }

    @Test
    fun totpFactorType_idProperty_shouldReturnTotpId() {
        // Given
        val customId = UUID.randomUUID()
        val totpInfo = TOTPFactorInfo(id = customId, secret = "JBSWY3DPEHPK3PXP")
        val factorType = FactorType.Totp(totpInfo)

        // When
        val id = factorType.id

        // Then
        assertEquals(customId, id)
    }

    @Test
    fun hotpFactorType_idProperty_shouldReturnHotpId() {
        // Given
        val customId = UUID.randomUUID()
        val hotpInfo = HOTPFactorInfo(id = customId, secret = "ON6MJUIM4MXYVLN3")
        val factorType = FactorType.Hotp(hotpInfo)

        // When
        val id = factorType.id

        // Then
        assertEquals(customId, id)
    }

    @Test
    fun biometricFactorType_idProperty_shouldReturnBiometricId() {
        // Given
        val customId = UUID.randomUUID()
        val biometricInfo = BiometricFactorInfo(id = customId)
        val factorType = FactorType.Biometric(biometricInfo)

        // When
        val id = factorType.id

        // Then
        assertEquals(customId, id)
    }

    @Test
    fun userPresenceFactorType_idProperty_shouldReturnUserPresenceId() {
        // Given
        val customId = UUID.randomUUID()
        val userPresenceInfo = UserPresenceFactorInfo(id = customId)
        val factorType = FactorType.UserPresence(userPresenceInfo)

        // When
        val id = factorType.id

        // Then
        assertEquals(customId, id)
    }

    @Test
    fun totpFactorType_displayNameProperty_shouldReturnTotpDisplayName() {
        // Given
        val customDisplayName = "Custom TOTP"
        val totpInfo = TOTPFactorInfo(displayName = customDisplayName, secret = "JBSWY3DPEHPK3PXP")
        val factorType = FactorType.Totp(totpInfo)

        // When
        val displayName = factorType.displayName

        // Then
        assertEquals(customDisplayName, displayName)
    }

    @Test
    fun hotpFactorType_displayNameProperty_shouldReturnHotpDisplayName() {
        // Given
        val customDisplayName = "Custom HOTP"
        val hotpInfo = HOTPFactorInfo(displayName = customDisplayName, secret = "ON6MJUIM4MXYVLN3")
        val factorType = FactorType.Hotp(hotpInfo)

        // When
        val displayName = factorType.displayName

        // Then
        assertEquals(customDisplayName, displayName)
    }

    @Test
    fun biometricFactorType_displayNameProperty_shouldReturnBiometricDisplayName() {
        // Given
        val customDisplayName = "Custom Biometric"
        val biometricInfo = BiometricFactorInfo(displayName = customDisplayName)
        val factorType = FactorType.Biometric(biometricInfo)

        // When
        val displayName = factorType.displayName

        // Then
        assertEquals(customDisplayName, displayName)
    }

    @Test
    fun userPresenceFactorType_displayNameProperty_shouldReturnUserPresenceDisplayName() {
        // Given
        val customDisplayName = "Custom User Presence"
        val userPresenceInfo = UserPresenceFactorInfo(displayName = customDisplayName)
        val factorType = FactorType.UserPresence(userPresenceInfo)

        // When
        val displayName = factorType.displayName

        // Then
        assertEquals(customDisplayName, displayName)
    }

    @Test
    fun valueType_withTotpFactorType_shouldReturnTotpInfo() {
        // Given
        val totpInfo = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val factorType: FactorType = FactorType.Totp(totpInfo)

        // When
        val result = factorType.valueType()

        // Then
        assertTrue(result is TOTPFactorInfo)
        assertEquals(totpInfo, result)
    }

    @Test
    fun valueType_withHotpFactorType_shouldReturnHotpInfo() {
        // Given
        val hotpInfo = HOTPFactorInfo(secret = "ON6MJUIM4MXYVLN3")
        val factorType: FactorType = FactorType.Hotp(hotpInfo)

        // When
        val result = factorType.valueType()

        // Then
        assertTrue(result is HOTPFactorInfo)
        assertEquals(hotpInfo, result)
    }

    @Test
    fun valueType_withBiometricFactorType_shouldReturnBiometricInfo() {
        // Given
        val biometricInfo = BiometricFactorInfo()
        val factorType: FactorType = FactorType.Biometric(biometricInfo)

        // When
        val result = factorType.valueType()

        // Then
        assertTrue(result is BiometricFactorInfo)
        assertEquals(biometricInfo, result)
    }

    @Test
    fun valueType_withUserPresenceFactorType_shouldReturnUserPresenceInfo() {
        // Given
        val userPresenceInfo = UserPresenceFactorInfo()
        val factorType: FactorType = FactorType.UserPresence(userPresenceInfo)

        // When
        val result = factorType.valueType()

        // Then
        assertTrue(result is UserPresenceFactorInfo)
        assertEquals(userPresenceInfo, result)
    }

    @Test
    fun serialization_totpFactorType_shouldSerializeAndDeserialize() {
        // Given
        val totpInfo = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val factorType = FactorType.Totp(totpInfo)
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(factorType)
        val deserialized = json.decodeFromString<FactorType.Totp>(serialized)

        // Then
        assertEquals(factorType.value.id, deserialized.value.id)
        assertEquals(factorType.value.displayName, deserialized.value.displayName)
        assertEquals(factorType.value.secret, deserialized.value.secret)
    }

    @Test
    fun serialization_hotpFactorType_shouldSerializeAndDeserialize() {
        // Given
        val hotpInfo = HOTPFactorInfo(secret = "ON6MJUIM4MXYVLN3")
        val factorType = FactorType.Hotp(hotpInfo)
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(factorType)
        val deserialized = json.decodeFromString<FactorType.Hotp>(serialized)

        // Then
        assertEquals(factorType.value.id, deserialized.value.id)
        assertEquals(factorType.value.displayName, deserialized.value.displayName)
        assertEquals(factorType.value.secret, deserialized.value.secret)
    }

    @Test
    fun serialization_biometricFactorType_shouldSerializeAndDeserialize() {
        // Given
        val biometricInfo = BiometricFactorInfo()
        val factorType = FactorType.Biometric(biometricInfo)
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(factorType)
        val deserialized = json.decodeFromString<FactorType.Biometric>(serialized)

        // Then
        assertEquals(factorType.value.id, deserialized.value.id)
        assertEquals(factorType.value.displayName, deserialized.value.displayName)
        assertEquals(factorType.value.keyName, deserialized.value.keyName)
    }

    @Test
    fun serialization_userPresenceFactorType_shouldSerializeAndDeserialize() {
        // Given
        val userPresenceInfo = UserPresenceFactorInfo()
        val factorType = FactorType.UserPresence(userPresenceInfo)
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(factorType)
        val deserialized = json.decodeFromString<FactorType.UserPresence>(serialized)

        // Then
        assertEquals(factorType.value.id, deserialized.value.id)
        assertEquals(factorType.value.displayName, deserialized.value.displayName)
        assertEquals(factorType.value.keyName, deserialized.value.keyName)
    }

    @Test
    fun sealedClass_shouldBeExhaustive() {
        // Given
        val totpInfo = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val hotpInfo = HOTPFactorInfo(secret = "ON6MJUIM4MXYVLN3")
        val biometricInfo = BiometricFactorInfo()
        val userPresenceInfo = UserPresenceFactorInfo()

        val factorTypes = listOf(
            FactorType.Totp(totpInfo),
            FactorType.Hotp(hotpInfo),
            FactorType.Biometric(biometricInfo),
            FactorType.UserPresence(userPresenceInfo)
        )

        // When/Then - Verify all types can be handled
        for (factorType in factorTypes) {
            when (factorType) {
                is FactorType.Totp -> assertNotNull(factorType.value)
                is FactorType.Hotp -> assertNotNull(factorType.value)
                is FactorType.Biometric -> assertNotNull(factorType.value)
                is FactorType.UserPresence -> assertNotNull(factorType.value)
            }
        }
    }

    @Test
    fun equals_totpFactorType_withSameValues_shouldReturnTrue() {
        // Given
        val id = UUID.randomUUID()
        val totpInfo1 = TOTPFactorInfo(id = id, secret = "JBSWY3DPEHPK3PXP")
        val totpInfo2 = TOTPFactorInfo(id = id, secret = "JBSWY3DPEHPK3PXP")
        val factorType1 = FactorType.Totp(totpInfo1)
        val factorType2 = FactorType.Totp(totpInfo2)

        // Then
        assertEquals(factorType1, factorType2)
    }

    @Test
    fun hashCode_totpFactorType_withSameValues_shouldReturnSameHashCode() {
        // Given
        val id = UUID.randomUUID()
        val totpInfo1 = TOTPFactorInfo(id = id, secret = "JBSWY3DPEHPK3PXP")
        val totpInfo2 = TOTPFactorInfo(id = id, secret = "JBSWY3DPEHPK3PXP")
        val factorType1 = FactorType.Totp(totpInfo1)
        val factorType2 = FactorType.Totp(totpInfo2)

        // Then
        assertEquals(factorType1.hashCode(), factorType2.hashCode())
    }

    @Test
    fun copy_totpFactorType_shouldCreateNewInstance() {
        // Given
        val totpInfo = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val original = FactorType.Totp(totpInfo)

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.value.id, copy.value.id)
        assertEquals(original.value.displayName, copy.value.displayName)
        assertEquals(original.value.secret, copy.value.secret)
    }

    @Test
    fun copy_hotpFactorType_shouldCreateNewInstance() {
        // Given
        val hotpInfo = HOTPFactorInfo(secret = "ON6MJUIM4MXYVLN3")
        val original = FactorType.Hotp(hotpInfo)

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.value.id, copy.value.id)
        assertEquals(original.value.displayName, copy.value.displayName)
        assertEquals(original.value.secret, copy.value.secret)
    }

    @Test
    fun toString_shouldContainFactorTypeInformation() {
        // Given
        val totpInfo = TOTPFactorInfo(secret = "JBSWY3DPEHPK3PXP")
        val factorType = FactorType.Totp(totpInfo)

        // When
        val result = factorType.toString()

        // Then
        assert(result.contains("Totp"))
    }
}
