/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.onprem

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import kotlin.time.ExperimentalTime
import com.ibm.security.verifysdk.mfa.BiometricFactorInfo
import com.ibm.security.verifysdk.mfa.HashAlgorithmType
import com.ibm.security.verifysdk.mfa.UserPresenceFactorInfo
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class OnPremiseAuthenticatorTest {

    private val testRefreshUri = URL("https://example.com/refresh")
    private val testTransactionUri = URL("https://example.com/transaction")
    private val testQrLoginUri = URL("https://example.com/qrlogin")
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
    private val testClientId = "client-id-123"

    @Test
    fun constructor_withRequiredFields_shouldCreateInstance() {
        // When
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = testQrLoginUri,
            clientId = testClientId
        )

        // Then
        assertEquals(testRefreshUri, authenticator.refreshUri)
        assertEquals(testTransactionUri, authenticator.transactionUri)
        assertEquals(testTheme, authenticator.theme)
        assertEquals(testToken, authenticator.token)
        assertEquals(testId, authenticator.id)
        assertEquals(testServiceName, authenticator.serviceName)
        assertEquals(testAccountName, authenticator.accountName)
        assertEquals(testQrLoginUri, authenticator.qrLoginUri)
        assertFalse(authenticator.ignoreSSLCertificate)
        assertEquals(testClientId, authenticator.clientId)
        assertNull(authenticator.biometric)
        assertNull(authenticator.userPresence)
    }

    @Test
    fun constructor_withNullQrLoginUri_shouldSetNull() {
        // When
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = null,
            clientId = testClientId
        )

        // Then
        assertNull(authenticator.qrLoginUri)
    }

    @Test
    fun constructor_withIgnoreSSLCertificateTrue_shouldSetTrue() {
        // When
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = testQrLoginUri,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )

        // Then
        assertTrue(authenticator.ignoreSSLCertificate)
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
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            biometric = biometric,
            qrLoginUri = testQrLoginUri,
            clientId = testClientId
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
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            userPresence = userPresence,
            qrLoginUri = testQrLoginUri,
            clientId = testClientId
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
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            biometric = biometric,
            userPresence = userPresence,
            qrLoginUri = testQrLoginUri,
            clientId = testClientId
        )

        // Then
        assertEquals(biometric, authenticator.biometric)
        assertEquals(userPresence, authenticator.userPresence)
    }

    @Test
    fun serialization_withRequiredFields_shouldSerializeAndDeserialize() {
        // Given
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = testQrLoginUri,
            clientId = testClientId
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(authenticator)
        val deserialized = json.decodeFromString<OnPremiseAuthenticator>(serialized)

        // Then
        assertEquals(authenticator.refreshUri, deserialized.refreshUri)
        assertEquals(authenticator.transactionUri, deserialized.transactionUri)
        assertEquals(authenticator.theme, deserialized.theme)
        assertEquals(authenticator.token.accessToken, deserialized.token.accessToken)
        assertEquals(authenticator.id, deserialized.id)
        assertEquals(authenticator.serviceName, deserialized.serviceName)
        assertEquals(authenticator.accountName, deserialized.accountName)
        assertEquals(authenticator.qrLoginUri, deserialized.qrLoginUri)
        assertEquals(authenticator.ignoreSSLCertificate, deserialized.ignoreSSLCertificate)
        assertEquals(authenticator.clientId, deserialized.clientId)
    }

    @Test
    fun serialization_withAllFields_shouldSerializeAndDeserialize() {
        // Given
        val biometric = BiometricFactorInfo()
        val userPresence = UserPresenceFactorInfo()
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            biometric = biometric,
            userPresence = userPresence,
            qrLoginUri = testQrLoginUri,
            ignoreSSLCertificate = true,
            clientId = testClientId
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(authenticator)
        val deserialized = json.decodeFromString<OnPremiseAuthenticator>(serialized)

        // Then
        assertEquals(authenticator.biometric?.id, deserialized.biometric?.id)
        assertEquals(authenticator.userPresence?.id, deserialized.userPresence?.id)
        assertEquals(authenticator.ignoreSSLCertificate, deserialized.ignoreSSLCertificate)
    }

    @Test
    fun equals_withDifferentId_shouldReturnFalse() {
        // Given
        val authenticator1 = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = "id1",
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = testQrLoginUri,
            clientId = testClientId
        )
        val authenticator2 = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = "id2",
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = testQrLoginUri,
            clientId = testClientId
        )

        // Then
        assertNotEquals(authenticator1, authenticator2)
    }

    @Test
    fun equals_withDifferentClientId_shouldReturnFalse() {
        // Given
        val authenticator1 = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = testQrLoginUri,
            clientId = "client1"
        )
        val authenticator2 = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = testQrLoginUri,
            clientId = "client2"
        )

        // Then
        assertNotEquals(authenticator1, authenticator2)
    }

    @Test
    fun hashCode_shouldReturnConsistentValue() {
        // Given
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = testQrLoginUri,
            clientId = testClientId
        )

        // When
        val hashCode1 = authenticator.hashCode()
        val hashCode2 = authenticator.hashCode()

        // Then - same instance should return same hashCode
        assertEquals(hashCode1, hashCode2)
    }
    
    @Test
    fun implementsMFAAuthenticatorDescriptor_shouldHaveRequiredProperties() {
        // Given
        val authenticator = OnPremiseAuthenticator(
            refreshUri = testRefreshUri,
            transactionUri = testTransactionUri,
            theme = testTheme,
            token = testToken,
            id = testId,
            serviceName = testServiceName,
            accountName = testAccountName,
            qrLoginUri = testQrLoginUri,
            clientId = testClientId
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
