/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.cloud

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.time.ExperimentalTime
import kotlin.time.Instant

@RunWith(AndroidJUnit4::class)
class TransactionResultTest {

    @OptIn(ExperimentalTime::class)
    private val testCreationTime = Instant.fromEpochMilliseconds(1640000000000)
    private val testTransactionInfo = "Test transaction data"
    private val testMethodInfo = TransactionResult.VerificationInfo.MethodInfo(
        id = "method-id-123",
        methodType = "signature",
        subType = "fingerprint"
    )

    @Test
    fun constructor_withDefaultValues_shouldCreateInstance() {
        // When
        val result = TransactionResult()

        // Then
        assertEquals(0, result.count)
        assertNull(result.verifications)
    }

    @Test
    fun constructor_withCount_shouldSetCount() {
        // When
        val result = TransactionResult(count = 5)

        // Then
        assertEquals(5, result.count)
        assertNull(result.verifications)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun constructor_withVerifications_shouldSetVerifications() {
        // Given
        val verification = TransactionResult.VerificationInfo(
            id = "verification-id-123",
            creationTime = testCreationTime,
            transactionInfo = testTransactionInfo,
            methodInfo = listOf(testMethodInfo)
        )

        // When
        val result = TransactionResult(
            count = 1,
            verifications = listOf(verification)
        )

        // Then
        assertEquals(1, result.count)
        assertNotNull(result.verifications)
        assertEquals(1, result.verifications?.size)
        assertEquals(verification, result.verifications?.get(0))
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun constructor_withMultipleVerifications_shouldSetAllVerifications() {
        // Given
        val verification1 = TransactionResult.VerificationInfo(
            id = "verification-1",
            creationTime = testCreationTime,
            transactionInfo = "Transaction 1",
            methodInfo = listOf(testMethodInfo)
        )
        val verification2 = TransactionResult.VerificationInfo(
            id = "verification-2",
            creationTime = testCreationTime,
            transactionInfo = "Transaction 2",
            methodInfo = listOf(testMethodInfo)
        )

        // When
        val result = TransactionResult(
            count = 2,
            verifications = listOf(verification1, verification2)
        )

        // Then
        assertEquals(2, result.count)
        assertEquals(2, result.verifications?.size)
    }

    @Test
    fun serialization_withDefaultValues_shouldSerializeAndDeserialize() {
        // Given
        val result = TransactionResult()
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(result)
        val deserialized = json.decodeFromString<TransactionResult>(serialized)

        // Then
        assertEquals(result.count, deserialized.count)
        assertEquals(result.verifications, deserialized.verifications)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun serialization_withVerifications_shouldSerializeAndDeserialize() {
        // Given
        val verification = TransactionResult.VerificationInfo(
            id = "verification-id-123",
            creationTime = testCreationTime,
            transactionInfo = testTransactionInfo,
            methodInfo = listOf(testMethodInfo)
        )
        val result = TransactionResult(count = 1, verifications = listOf(verification))
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(result)
        val deserialized = json.decodeFromString<TransactionResult>(serialized)

        // Then
        assertEquals(result.count, deserialized.count)
        assertEquals(result.verifications?.size, deserialized.verifications?.size)
        assertEquals(result.verifications?.get(0)?.id, deserialized.verifications?.get(0)?.id)
    }

    @Test
    fun deserialization_fromJsonString_shouldCreateInstance() {
        // Given
        val jsonString = """
            {
                "total": 1,
                "verifications": []
            }
        """.trimIndent()
        val json = Json { ignoreUnknownKeys = true }

        // When
        val result = json.decodeFromString<TransactionResult>(jsonString)

        // Then
        assertEquals(1, result.count)
        assertNotNull(result.verifications)
        assertTrue(result.verifications!!.isEmpty())
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = TransactionResult(count = 3)

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.count, copy.count)
        assertEquals(original.verifications, copy.verifications)
    }

    @Test
    fun copy_withModifiedCount_shouldUpdateOnlyCount() {
        // Given
        val original = TransactionResult(count = 3)

        // When
        val modified = original.copy(count = 5)

        // Then
        assertEquals(5, modified.count)
        assertEquals(original.verifications, modified.verifications)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun copy_withModifiedVerifications_shouldUpdateOnlyVerifications() {
        // Given
        val verification = TransactionResult.VerificationInfo(
            id = "verification-id",
            creationTime = testCreationTime,
            transactionInfo = testTransactionInfo,
            methodInfo = listOf(testMethodInfo)
        )
        val original = TransactionResult(count = 1)

        // When
        val modified = original.copy(verifications = listOf(verification))

        // Then
        assertEquals(original.count, modified.count)
        assertNotNull(modified.verifications)
        assertEquals(1, modified.verifications?.size)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val result1 = TransactionResult(count = 3)
        val result2 = TransactionResult(count = 3)

        // Then
        assertEquals(result1, result2)
    }

    @Test
    fun equals_withDifferentCount_shouldReturnFalse() {
        // Given
        val result1 = TransactionResult(count = 3)
        val result2 = TransactionResult(count = 5)

        // Then
        assertNotEquals(result1, result2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val result1 = TransactionResult(count = 3)
        val result2 = TransactionResult(count = 3)

        // Then
        assertEquals(result1.hashCode(), result2.hashCode())
    }

    @Test
    fun toString_shouldContainProperties() {
        // Given
        val result = TransactionResult(count = 5)

        // When
        val resultString = result.toString()

        // Then
        assert(resultString.contains("TransactionResult"))
        assert(resultString.contains("5"))
    }

    // VerificationInfo tests
    @OptIn(ExperimentalTime::class)
    @Test
    fun verificationInfo_constructor_shouldCreateInstance() {
        // When
        val verification = TransactionResult.VerificationInfo(
            id = "verification-id-123",
            creationTime = testCreationTime,
            transactionInfo = testTransactionInfo,
            methodInfo = listOf(testMethodInfo)
        )

        // Then
        assertEquals("verification-id-123", verification.id)
        assertEquals(testCreationTime, verification.creationTime)
        assertEquals(testTransactionInfo, verification.transactionInfo)
        assertEquals(1, verification.methodInfo.size)
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun verificationInfo_withMultipleMethods_shouldSetAllMethods() {
        // Given
        val method1 = TransactionResult.VerificationInfo.MethodInfo("id1", "type1", "subType1")
        val method2 = TransactionResult.VerificationInfo.MethodInfo("id2", "type2", "subType2")

        // When
        val verification = TransactionResult.VerificationInfo(
            id = "verification-id",
            creationTime = testCreationTime,
            transactionInfo = testTransactionInfo,
            methodInfo = listOf(method1, method2)
        )

        // Then
        assertEquals(2, verification.methodInfo.size)
        assertEquals(method1, verification.methodInfo[0])
        assertEquals(method2, verification.methodInfo[1])
    }

    @OptIn(ExperimentalTime::class)
    @Test
    fun verificationInfo_serialization_shouldSerializeAndDeserialize() {
        // Given
        val verification = TransactionResult.VerificationInfo(
            id = "verification-id-123",
            creationTime = testCreationTime,
            transactionInfo = testTransactionInfo,
            methodInfo = listOf(testMethodInfo)
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(verification)
        val deserialized = json.decodeFromString<TransactionResult.VerificationInfo>(serialized)

        // Then
        assertEquals(verification.id, deserialized.id)
        assertEquals(verification.transactionInfo, deserialized.transactionInfo)
        assertEquals(verification.methodInfo.size, deserialized.methodInfo.size)
    }

    // MethodInfo tests
    @Test
    fun methodInfo_constructor_shouldCreateInstance() {
        // When
        val methodInfo = TransactionResult.VerificationInfo.MethodInfo(
            id = "method-id-123",
            methodType = "signature",
            subType = "fingerprint"
        )

        // Then
        assertEquals("method-id-123", methodInfo.id)
        assertEquals("signature", methodInfo.methodType)
        assertEquals("fingerprint", methodInfo.subType)
    }

    @Test
    fun methodInfo_serialization_shouldSerializeAndDeserialize() {
        // Given
        val methodInfo = TransactionResult.VerificationInfo.MethodInfo(
            id = "method-id-123",
            methodType = "signature",
            subType = "fingerprint"
        )
        val json = Json { prettyPrint = true }

        // When
        val serialized = json.encodeToString(methodInfo)
        val deserialized = json.decodeFromString<TransactionResult.VerificationInfo.MethodInfo>(serialized)

        // Then
        assertEquals(methodInfo.id, deserialized.id)
        assertEquals(methodInfo.methodType, deserialized.methodType)
        assertEquals(methodInfo.subType, deserialized.subType)
    }

    @Test
    fun methodInfo_equals_withSameValues_shouldReturnTrue() {
        // Given
        val method1 = TransactionResult.VerificationInfo.MethodInfo("id", "type", "subType")
        val method2 = TransactionResult.VerificationInfo.MethodInfo("id", "type", "subType")

        // Then
        assertEquals(method1, method2)
    }

    @Test
    fun methodInfo_equals_withDifferentId_shouldReturnFalse() {
        // Given
        val method1 = TransactionResult.VerificationInfo.MethodInfo("id1", "type", "subType")
        val method2 = TransactionResult.VerificationInfo.MethodInfo("id2", "type", "subType")

        // Then
        assertNotEquals(method1, method2)
    }

    @Test
    fun methodInfo_copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = TransactionResult.VerificationInfo.MethodInfo("id", "type", "subType")

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.id, copy.id)
        assertEquals(original.methodType, copy.methodType)
        assertEquals(original.subType, copy.subType)
    }

    @Test
    fun methodInfo_copy_withModifiedId_shouldUpdateOnlyId() {
        // Given
        val original = TransactionResult.VerificationInfo.MethodInfo("id", "type", "subType")

        // When
        val modified = original.copy(id = "new-id")

        // Then
        assertEquals("new-id", modified.id)
        assertEquals(original.methodType, modified.methodType)
        assertEquals(original.subType, modified.subType)
    }

    @Test
    fun methodInfo_toString_shouldContainAllProperties() {
        // Given
        val methodInfo = TransactionResult.VerificationInfo.MethodInfo("id", "type", "subType")

        // When
        val result = methodInfo.toString()

        // Then
        assert(result.contains("MethodInfo"))
        assert(result.contains("id"))
        assert(result.contains("type"))
        assert(result.contains("subType"))
    }
}


