/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import java.util.UUID
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@OptIn(ExperimentalTime::class)
@RunWith(AndroidJUnit4::class)
class PendingTransactionInfoTest {

    @Test
    fun constructor_withAllParameters_shouldCreateInstance() {
        // Given
        val id = "12345678-1234-1234-1234-123456789012"
        val message = "Login attempt"
        val postbackUri = URL("https://example.com/postback")
        val factorID = UUID.randomUUID()
        val factorType = "signature"
        val dataToSign = "data123"
        val timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis())
        val additionalData = mapOf(
            TransactionAttribute.IPAddress to "192.168.1.1",
            TransactionAttribute.Location to "New York"
        )

        // When
        val transaction = PendingTransactionInfo(
            id = id,
            message = message,
            postbackUri = postbackUri,
            factorID = factorID,
            factorType = factorType,
            dataToSign = dataToSign,
            timeStamp = timeStamp,
            additionalData = additionalData
        )

        // Then
        assertEquals(id, transaction.id)
        assertEquals(message, transaction.message)
        assertEquals(postbackUri, transaction.postbackUri)
        assertEquals(factorID, transaction.factorID)
        assertEquals(factorType, transaction.factorType)
        assertEquals(dataToSign, transaction.dataToSign)
        assertEquals(timeStamp, transaction.timeStamp)
        assertEquals(additionalData, transaction.additionalData)
    }

    @Test
    fun shortId_shouldReturnIdBeforeFirstDash() {
        // Given
        val id = "12345678-1234-1234-1234-123456789012"
        val transaction = PendingTransactionInfo(
            id = id,
            message = "Test",
            postbackUri = URL("https://example.com"),
            factorID = UUID.randomUUID(),
            factorType = "signature",
            dataToSign = "data",
            timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis()),
            additionalData = emptyMap()
        )

        // When
        val shortId = transaction.shortId

        // Then
        assertEquals("12345678", shortId)
    }

    @Test
    fun shortId_withDifferentId_shouldReturnCorrectShortId() {
        // Given
        val id = "abcdefgh-5678-9012-3456-789012345678"
        val transaction = PendingTransactionInfo(
            id = id,
            message = "Test",
            postbackUri = URL("https://example.com"),
            factorID = UUID.randomUUID(),
            factorType = "signature",
            dataToSign = "data",
            timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis()),
            additionalData = emptyMap()
        )

        // When
        val shortId = transaction.shortId

        // Then
        assertEquals("abcdefgh", shortId)
    }

    @Test
    fun additionalData_withMultipleAttributes_shouldStoreAllAttributes() {
        // Given
        val additionalData = mapOf(
            TransactionAttribute.IPAddress to "10.0.0.1",
            TransactionAttribute.Location to "London",
            TransactionAttribute.UserAgent to "Mozilla/5.0",
            TransactionAttribute.Type to "login",
            TransactionAttribute.Custom to "custom_value"
        )
        val transaction = PendingTransactionInfo(
            id = "test-id",
            message = "Test",
            postbackUri = URL("https://example.com"),
            factorID = UUID.randomUUID(),
            factorType = "signature",
            dataToSign = "data",
            timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis()),
            additionalData = additionalData
        )

        // Then
        assertEquals(5, transaction.additionalData.size)
        assertEquals("10.0.0.1", transaction.additionalData[TransactionAttribute.IPAddress])
        assertEquals("London", transaction.additionalData[TransactionAttribute.Location])
        assertEquals("Mozilla/5.0", transaction.additionalData[TransactionAttribute.UserAgent])
        assertEquals("login", transaction.additionalData[TransactionAttribute.Type])
        assertEquals("custom_value", transaction.additionalData[TransactionAttribute.Custom])
    }

    @Test
    fun additionalData_withEmptyMap_shouldCreateInstance() {
        // Given
        val additionalData = emptyMap<TransactionAttribute, String>()

        // When
        val transaction = PendingTransactionInfo(
            id = "test-id",
            message = "Test",
            postbackUri = URL("https://example.com"),
            factorID = UUID.randomUUID(),
            factorType = "signature",
            dataToSign = "data",
            timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis()),
            additionalData = additionalData
        )

        // Then
        assertTrue(transaction.additionalData.isEmpty())
    }

    @Test
    fun serialization_shouldSerializeAndDeserialize() {
        // Given
        val factorID = UUID.randomUUID()
        val timeStamp = Instant.fromEpochMilliseconds(1609459200000) // 2021-01-01 00:00:00 UTC
        val transaction = PendingTransactionInfo(
            id = "test-id-1234",
            message = "Login request",
            postbackUri = URL("https://example.com/callback"),
            factorID = factorID,
            factorType = "signature",
            dataToSign = "signme",
            timeStamp = timeStamp,
            additionalData = mapOf(TransactionAttribute.IPAddress to "192.168.1.1")
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(transaction)
        val deserialized = json.decodeFromString<PendingTransactionInfo>(serialized)

        // Then
        assertEquals(transaction.id, deserialized.id)
        assertEquals(transaction.message, deserialized.message)
        assertEquals(transaction.postbackUri, deserialized.postbackUri)
        assertEquals(transaction.factorID, deserialized.factorID)
        assertEquals(transaction.factorType, deserialized.factorType)
        assertEquals(transaction.dataToSign, deserialized.dataToSign)
        assertEquals(transaction.timeStamp, deserialized.timeStamp)
        assertEquals(transaction.additionalData.size, deserialized.additionalData.size)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = PendingTransactionInfo(
            id = "original-id",
            message = "Original message",
            postbackUri = URL("https://example.com"),
            factorID = UUID.randomUUID(),
            factorType = "signature",
            dataToSign = "data",
            timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis()),
            additionalData = mapOf(TransactionAttribute.IPAddress to "192.168.1.1")
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.id, copy.id)
        assertEquals(original.message, copy.message)
        assertEquals(original.postbackUri, copy.postbackUri)
        assertEquals(original.factorID, copy.factorID)
        assertEquals(original.factorType, copy.factorType)
        assertEquals(original.dataToSign, copy.dataToSign)
        assertEquals(original.timeStamp, copy.timeStamp)
        assertEquals(original.additionalData, copy.additionalData)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val id = "test-id"
        val factorID = UUID.randomUUID()
        val timeStamp = Instant.fromEpochMilliseconds(1609459200000)
        val transaction1 = PendingTransactionInfo(
            id = id,
            message = "Test",
            postbackUri = URL("https://example.com"),
            factorID = factorID,
            factorType = "signature",
            dataToSign = "data",
            timeStamp = timeStamp,
            additionalData = emptyMap()
        )
        val transaction2 = PendingTransactionInfo(
            id = id,
            message = "Test",
            postbackUri = URL("https://example.com"),
            factorID = factorID,
            factorType = "signature",
            dataToSign = "data",
            timeStamp = timeStamp,
            additionalData = emptyMap()
        )

        // Then
        assertEquals(transaction1, transaction2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val id = "test-id"
        val factorID = UUID.randomUUID()
        val timeStamp = Instant.fromEpochMilliseconds(1609459200000)
        val transaction1 = PendingTransactionInfo(
            id = id,
            message = "Test",
            postbackUri = URL("https://example.com"),
            factorID = factorID,
            factorType = "signature",
            dataToSign = "data",
            timeStamp = timeStamp,
            additionalData = emptyMap()
        )
        val transaction2 = PendingTransactionInfo(
            id = id,
            message = "Test",
            postbackUri = URL("https://example.com"),
            factorID = factorID,
            factorType = "signature",
            dataToSign = "data",
            timeStamp = timeStamp,
            additionalData = emptyMap()
        )

        // Then
        assertEquals(transaction1.hashCode(), transaction2.hashCode())
    }

    @Test
    fun toString_shouldContainTransactionInformation() {
        // Given
        val transaction = PendingTransactionInfo(
            id = "test-id",
            message = "Test message",
            postbackUri = URL("https://example.com"),
            factorID = UUID.randomUUID(),
            factorType = "signature",
            dataToSign = "data",
            timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis()),
            additionalData = emptyMap()
        )

        // When
        val result = transaction.toString()

        // Then
        assertNotNull(result)
        assertTrue(result.contains("PendingTransactionInfo"))
    }

    @Test
    fun postbackUri_shouldSupportDifferentProtocols() {
        // Given
        val httpsUri = URL("https://secure.example.com/callback")
        val httpUri = URL("http://example.com/callback")

        // When
        val transaction1 = PendingTransactionInfo(
            id = "test-1",
            message = "Test",
            postbackUri = httpsUri,
            factorID = UUID.randomUUID(),
            factorType = "signature",
            dataToSign = "data",
            timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis()),
            additionalData = emptyMap()
        )
        val transaction2 = PendingTransactionInfo(
            id = "test-2",
            message = "Test",
            postbackUri = httpUri,
            factorID = UUID.randomUUID(),
            factorType = "signature",
            dataToSign = "data",
            timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis()),
            additionalData = emptyMap()
        )

        // Then
        assertEquals("https", transaction1.postbackUri.protocol)
        assertEquals("http", transaction2.postbackUri.protocol)
    }

    @Test
    fun factorType_shouldAcceptDifferentTypes() {
        // Given
        val types = listOf("signature", "totp", "hotp", "biometric", "user_presence")

        // When/Then
        for (type in types) {
            val transaction = PendingTransactionInfo(
                id = "test-id",
                message = "Test",
                postbackUri = URL("https://example.com"),
                factorID = UUID.randomUUID(),
                factorType = type,
                dataToSign = "data",
                timeStamp = Instant.fromEpochMilliseconds(System.currentTimeMillis()),
                additionalData = emptyMap()
            )
            assertEquals(type, transaction.factorType)
        }
    }
}
