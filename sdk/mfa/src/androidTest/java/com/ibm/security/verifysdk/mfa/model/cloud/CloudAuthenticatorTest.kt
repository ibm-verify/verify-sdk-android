/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.cloud

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import kotlin.time.ExperimentalTime
import com.ibm.security.verifysdk.mfa.BiometricFactorInfo
import com.ibm.security.verifysdk.mfa.HashAlgorithmType
import com.ibm.security.verifysdk.mfa.UserPresenceFactorInfo
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class CloudAuthenticatorTest {

    private val testRefreshUri = URL("https://example.com/refresh")
    private val testTransactionUri = URL("https://example.com/transaction")
    private val testTheme = mapOf("color" to "blue", "logo" to "https://example.com/logo.png")
    @OptIn(ExperimentalTime::class)
    private val testToken = TokenInfo(
        accessToken = "access_token_123",
        refreshToken = "refresh_token_456",
        expiresIn = 3600,
        tokenType = "Bearer",
        additionalData = emptyMap()
    )
    private val testId = "test-id-123"
    private val testServiceName = "Test Service"
    private val testAccountName = "test@example.com"
    private val testCustomAttributes = mapOf("attr1" to "value1", "attr2" to "value2")

    @Test
    fun constructor_withRequiredFields_shouldCreateInstance() {
        // When
        val authenticator = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )

        // Then
        assertEquals(testRefreshUri, authenticator.refreshUri)
        assertEquals(testTransactionUri, authenticator.transactionUri)
        assertEquals(testTheme, authenticator.theme)
        assertEquals(testToken, authenticator.token)
        assertEquals(testId, authenticator.id)
        assertEquals(testServiceName, authenticator.serviceName)
        assertEquals(testAccountName, authenticator.accountName)
        assertEquals(testCustomAttributes, authenticator.customAttributes)
        assertNull(authenticator.biometric)
        assertNull(authenticator.userPresence)
    }

    @Test
    fun constructor_withBiometric_shouldSetBiometric() {
        // Given
        val biometric = BiometricFactorInfo(
            id = UUID.randomUUID(),
            displayName = "Fingerprint",
            keyName = "fingerprint_key",
            algorithm = HashAlgorithmType.SHA256
        )

        // When
        val authenticator = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            biometric = biometric,
            customAttributes = testCustomAttributes
        )

        // Then
        assertEquals(biometric, authenticator.biometric)
        assertNull(authenticator.userPresence)
    }

    @Test
    fun constructor_withUserPresence_shouldSetUserPresence() {
        // Given
        val userPresence = UserPresenceFactorInfo(
            id = UUID.randomUUID(),
            displayName = "User Presence",
            keyName = "user_presence_key",
            algorithm = HashAlgorithmType.SHA512
        )

        // When
        val authenticator = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            userPresence = userPresence,
            customAttributes = testCustomAttributes
        )

        // Then
        assertNull(authenticator.biometric)
        assertEquals(userPresence, authenticator.userPresence)
    }

    @Test
    fun constructor_withBothFactors_shouldSetBothFactors() {
        // Given
        val biometric = BiometricFactorInfo()
        val userPresence = UserPresenceFactorInfo()

        // When
        val authenticator = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            biometric = biometric,
            userPresence = userPresence,
            customAttributes = testCustomAttributes
        )

        // Then
        assertEquals(biometric, authenticator.biometric)
        assertEquals(userPresence, authenticator.userPresence)
    }

    @Test
    fun serialization_withRequiredFields_shouldSerializeAndDeserialize() {
        // Given
        val authenticator = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(authenticator)
        val deserialized = json.decodeFromString<CloudAuthenticator>(serialized)

        // Then
        assertEquals(authenticator.refreshUri, deserialized.refreshUri)
        assertEquals(authenticator.transactionUri, deserialized.transactionUri)
        assertEquals(authenticator.theme, deserialized.theme)
        assertEquals(authenticator.token.accessToken, deserialized.token.accessToken)
        assertEquals(authenticator.id, deserialized.id)
        assertEquals(authenticator.serviceName, deserialized.serviceName)
        assertEquals(authenticator.accountName, deserialized.accountName)
        assertEquals(authenticator.customAttributes, deserialized.customAttributes)
    }

    @Test
    fun serialization_withAllFields_shouldSerializeAndDeserialize() {
        // Given
        val biometric = BiometricFactorInfo()
        val userPresence = UserPresenceFactorInfo()
        val authenticator = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            biometric = biometric,
            userPresence = userPresence,
            customAttributes = testCustomAttributes
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(authenticator)
        val deserialized = json.decodeFromString<CloudAuthenticator>(serialized)

        // Then
        assertEquals(authenticator.biometric?.id, deserialized.biometric?.id)
        assertEquals(authenticator.userPresence?.id, deserialized.userPresence?.id)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.refreshUri, copy.refreshUri)
        assertEquals(original.transactionUri, copy.transactionUri)
        assertEquals(original.theme, copy.theme)
        assertEquals(original.token, copy.token)
        assertEquals(original.id, copy.id)
        assertEquals(original.serviceName, copy.serviceName)
        assertEquals(original.accountName, copy.accountName)
        assertEquals(original.customAttributes, copy.customAttributes)
    }

    @Test
    fun copy_withModifiedAccountName_shouldUpdateOnlyAccountName() {
        // Given
        val original = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )

        // When
        val modified = original.copy(accountName = "new@example.com")

        // Then
        assertEquals(original.refreshUri, modified.refreshUri)
        assertEquals("new@example.com", modified.accountName)
        assertEquals(original.id, modified.id)
    }

    @Test
    fun copy_withModifiedTheme_shouldUpdateOnlyTheme() {
        // Given
        val original = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )
        val newTheme = mapOf("color" to "red")

        // When
        val modified = original.copy(theme = newTheme)

        // Then
        assertEquals(newTheme, modified.theme)
        assertEquals(original.accountName, modified.accountName)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val authenticator1 = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )
        val authenticator2 = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )

        // Then
        assertEquals(authenticator1, authenticator2)
    }

    @Test
    fun equals_withDifferentId_shouldReturnFalse() {
        // Given
        val authenticator1 = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = "id1",
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )
        val authenticator2 = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = "id2",
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )

        // Then
        assertNotEquals(authenticator1, authenticator2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given - Create a shared token to ensure same reference
        val sharedToken = testToken
        val authenticator1 = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = sharedToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )
        val authenticator2 = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = sharedToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )

        // Then - data classes with same values should have same hashCode
        assertEquals(authenticator1.hashCode(), authenticator2.hashCode())
    }

    @Test
    fun toString_shouldContainAllProperties() {
        // Given
        val authenticator = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )

        // When
        val result = authenticator.toString()

        // Then
        assert(result.contains("CloudAuthenticator"))
        assert(result.contains(testId))
        assert(result.contains(testServiceName))
        assert(result.contains(testAccountName))
    }

    @Test
    fun implementsMFAAuthenticatorDescriptor_shouldHaveRequiredProperties() {
        // Given
        val authenticator = CloudAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            customAttributes = testCustomAttributes
        )

        // Then
        assertNotNull(authenticator.refreshUri)
        assertNotNull(authenticator.transactionUri)
        assertNotNull(authenticator.theme)
        assertNotNull(authenticator.token)
        assertNotNull(authenticator.id)
        assertNotNull(authenticator.serviceName)
        assertNotNull(authenticator.accountName)
    }
}


