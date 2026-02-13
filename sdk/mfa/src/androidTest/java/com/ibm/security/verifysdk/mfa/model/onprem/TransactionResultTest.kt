/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.onprem

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@RunWith(AndroidJUnit4::class)
class TransactionResultTest {

    @OptIn(ExperimentalTime::class)
    private val testCreationTime = Instant.fromEpochMilliseconds(1640000000000)
    private val testRequestUrl = "https://example.com/request"
    private val testTransactionId = "transaction-id-123"
    private val testAuthnPolicyUri = "https://example.com/policy"

    @Test
    fun constructor_withDefaultValues_shouldCreateInstance() {
        // When
        val result = TransactionResult()

        // Then
        assertTrue(result.transactions.isEmpty())
        assertTrue(result.attributes.isEmpty())
    }

    @Test
    fun constructor_withTransactions_shouldSetTransactions() {
        // Given
        @OptIn(ExperimentalTime::class)
        val transaction = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )

        // When
        val result = TransactionResult(transactions = listOf(transaction))

        // Then
        assertEquals(1, result.transactions.size)
        assertEquals(transaction, result.transactions[0])
        assertTrue(result.attributes.isEmpty())
    }

    @Test
    fun constructor_withAttributes_shouldSetAttributes() {
        // Given
        val attribute = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1", "value2"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // When
        val result = TransactionResult(attributes = listOf(attribute))

        // Then
        assertTrue(result.transactions.isEmpty())
        assertEquals(1, result.attributes.size)
        assertEquals(attribute, result.attributes[0])
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun constructor_withBothTransactionsAndAttributes_shouldSetBoth() {
        // Given
        val transaction = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )
        val attribute = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // When
        val result = TransactionResult(
            transactions = listOf(transaction),
            attributes = listOf(attribute)
        )

        // Then
        assertEquals(1, result.transactions.size)
        assertEquals(1, result.attributes.size)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun serialization_withTransactions_shouldSerializeAndDeserialize() {
        // Given
        val transaction = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )
        val result = TransactionResult(transactions = listOf(transaction))
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(result)
        val deserialized = json.decodeFromString<TransactionResult>(serialized)

        // Then
        assertEquals(result.transactions.size, deserialized.transactions.size)
        assertEquals(result.transactions[0].transactionId, deserialized.transactions[0].transactionId)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = TransactionResult()

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.transactions, copy.transactions)
        assertEquals(original.attributes, copy.attributes)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun copy_withModifiedTransactions_shouldUpdateOnlyTransactions() {
        // Given
        val original = TransactionResult()
        val transaction = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )

        // When
        val modified = original.copy(transactions = listOf(transaction))

        // Then
        assertEquals(1, modified.transactions.size)
        assertEquals(original.attributes, modified.attributes)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val result1 = TransactionResult()
        val result2 = TransactionResult()

        // Then
        assertEquals(result1, result2)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun equals_withDifferentTransactions_shouldReturnFalse() {
        // Given
        val transaction = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )
        val result1 = TransactionResult(transactions = listOf(transaction))
        val result2 = TransactionResult()

        // Then
        assertNotEquals(result1, result2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val result1 = TransactionResult()
        val result2 = TransactionResult()

        // Then
        assertEquals(result1.hashCode(), result2.hashCode())
    }

    @Test
    fun toString_shouldContainProperties() {
        // Given
        val result = TransactionResult()

        // When
        val resultString = result.toString()

        // Then
        assert(resultString.contains("TransactionResult"))
    }

    // TransactionInfo tests
    @OptIn(ExperimentalTime::class)
    @Test
    fun transactionInfo_constructor_shouldCreateInstance() {
        // When
        val transaction = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )

        // Then
        assertEquals(testCreationTime, transaction.creationTime)
        assertEquals(testRequestUrl, transaction.requestUrl)
        assertEquals(testTransactionId, transaction.transactionId)
        assertEquals(testAuthnPolicyUri, transaction.authnPolicyUri)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun transactionInfo_serialization_shouldSerializeAndDeserialize() {
        // Given
        val transaction = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(transaction)
        val deserialized = json.decodeFromString<TransactionResult.TransactionInfo>(serialized)

        // Then
        assertEquals(transaction.requestUrl, deserialized.requestUrl)
        assertEquals(transaction.transactionId, deserialized.transactionId)
        assertEquals(transaction.authnPolicyUri, deserialized.authnPolicyUri)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun transactionInfo_copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.creationTime, copy.creationTime)
        assertEquals(original.requestUrl, copy.requestUrl)
        assertEquals(original.transactionId, copy.transactionId)
        assertEquals(original.authnPolicyUri, copy.authnPolicyUri)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun transactionInfo_equals_withSameValues_shouldReturnTrue() {
        // Given
        val transaction1 = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )
        val transaction2 = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = testTransactionId,
            authnPolicyUri = testAuthnPolicyUri
        )

        // Then
        assertEquals(transaction1, transaction2)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun transactionInfo_equals_withDifferentTransactionId_shouldReturnFalse() {
        // Given
        val transaction1 = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = "id1",
            authnPolicyUri = testAuthnPolicyUri
        )
        val transaction2 = TransactionResult.TransactionInfo(
            creationTime = testCreationTime,
            requestUrl = testRequestUrl,
            transactionId = "id2",
            authnPolicyUri = testAuthnPolicyUri
        )

        // Then
        assertNotEquals(transaction1, transaction2)
    }

    // AttributeInfo tests
    @Test
    fun attributeInfo_constructor_shouldCreateInstance() {
        // When
        val attribute = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1", "value2"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // Then
        assertEquals("string", attribute.dataType)
        assertEquals(2, attribute.values.size)
        assertEquals("https://example.com/attribute", attribute.uri)
        assertEquals(testTransactionId, attribute.transactionId)
    }

    @Test
    fun attributeInfo_withEmptyValues_shouldSetEmptyList() {
        // When
        val attribute = TransactionResult.AttributeInfo(
            dataType = "string",
            values = emptyList(),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // Then
        assertTrue(attribute.values.isEmpty())
    }

    @Test
    fun attributeInfo_serialization_shouldSerializeAndDeserialize() {
        // Given
        val attribute = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1", "value2"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(attribute)
        val deserialized = json.decodeFromString<TransactionResult.AttributeInfo>(serialized)

        // Then
        assertEquals(attribute.dataType, deserialized.dataType)
        assertEquals(attribute.values, deserialized.values)
        assertEquals(attribute.uri, deserialized.uri)
        assertEquals(attribute.transactionId, deserialized.transactionId)
    }

    @Test
    fun attributeInfo_copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.dataType, copy.dataType)
        assertEquals(original.values, copy.values)
        assertEquals(original.uri, copy.uri)
        assertEquals(original.transactionId, copy.transactionId)
    }

    @Test
    fun attributeInfo_copy_withModifiedDataType_shouldUpdateOnlyDataType() {
        // Given
        val original = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // When
        val modified = original.copy(dataType = "integer")

        // Then
        assertEquals("integer", modified.dataType)
        assertEquals(original.values, modified.values)
        assertEquals(original.uri, modified.uri)
    }

    @Test
    fun attributeInfo_equals_withSameValues_shouldReturnTrue() {
        // Given
        val attribute1 = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )
        val attribute2 = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // Then
        assertEquals(attribute1, attribute2)
    }

    @Test
    fun attributeInfo_equals_withDifferentDataType_shouldReturnFalse() {
        // Given
        val attribute1 = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )
        val attribute2 = TransactionResult.AttributeInfo(
            dataType = "integer",
            values = listOf("value1"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // Then
        assertNotEquals(attribute1, attribute2)
    }

    @Test
    fun attributeInfo_toString_shouldContainAllProperties() {
        // Given
        val attribute = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // When
        val result = attribute.toString()

        // Then
        assert(result.contains("AttributeInfo"))
        assert(result.contains("string"))
        assert(result.contains(testTransactionId))
    }

    @Test
    fun attributeInfo_allProperties_shouldNotBeNull() {
        // Given
        val attribute = TransactionResult.AttributeInfo(
            dataType = "string",
            values = listOf("value1"),
            uri = "https://example.com/attribute",
            transactionId = testTransactionId
        )

        // Then
        assertNotNull(attribute.dataType)
        assertNotNull(attribute.values)
        assertNotNull(attribute.uri)
        assertNotNull(attribute.transactionId)
    }
}


