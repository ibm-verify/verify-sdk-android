/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import android.annotation.SuppressLint
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.mfa.TokenPersistenceCallback
import com.ibm.security.verifysdk.mfa.TransactionAttribute
import com.ibm.security.verifysdk.mfa.UserAction
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import kotlin.time.ExperimentalTime

/**
 * Integration test suite based on real network traces.
 * 
 * This test suite validates the complete MFA flow:
 * 1. Token refresh after enrollment
 * 2. Fetch pending transactions
 * 3. Transaction completion
 * 4. Transaction data parsing
 * 
 * All sensitive data has been sanitized while preserving the structure and flow.
 * 
 * Note: Registration and factor enrollment tests are covered in CloudRegistrationProviderTest.
 */
@OptIn(ExperimentalTime::class)
@RunWith(AndroidJUnit4::class)
class CloudAuthenticatorIntegrationTest {

    @Before
    fun setup() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        ContextHelper.init(appContext)
    }

    /**
     * Test Case 1: Token Refresh After Enrollment
     * 
     * Based on log lines 433-464:
     * - POST to /v1.0/authenticators/registration?metadataInResponse=false
     * - Uses refreshToken to get new access token
     */
    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testTokenRefreshAfterEnrollment_shouldReturnNewTokens(): Unit = runBlocking {
        var persistedToken: TokenInfo? = null
        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                persistedToken = newToken
                return Result.success(Unit)
            }
        }

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/registration") -> {
                    respond(
                        content = """
                        {
                          "expiresIn": 3600,
                          "id": "test-authenticator-id",
                          "accessToken": "new_access_token_after_enrollment",
                          "version": {
                            "number": "1.0.0",
                            "platform": "com.ibm.security.access.verify"
                          },
                          "refreshToken": "new_refresh_token_after_enrollment"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        }

        val httpClient = HttpClient(mockEngine)
        val service = CloudAuthenticatorService(
            _accessToken = "old_access_token",
            _refreshUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/registration"),
            _transactionUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test-authenticator-id",
            httpClient = httpClient,
            persistenceCallback = callback
        )

        val result = service.refreshToken(
            refreshToken = "old_refresh_token",
            accountName = "test@example.com",
            pushToken = "test_push_token",
            additionalData = null
        )

        assertTrue("Token refresh should succeed", result.isSuccess)
        result.onSuccess { newToken ->
            assertEquals("new_access_token_after_enrollment", newToken.accessToken)
            assertEquals("new_refresh_token_after_enrollment", newToken.refreshToken)
            assertEquals(3600, newToken.expiresIn)
        }

        assertNotNull("Token should be persisted", persistedToken)
        assertEquals("new_access_token_after_enrollment", persistedToken?.accessToken)

        httpClient.close()
    }

    /**
     * Test Case 2: Fetch Pending Transaction
     * 
     * Based on log lines 492-529:
     * - GET to /v1.0/authenticators/{id}/verifications with state="PENDING"
     * - Response includes transaction data with message, IP, user agent
     */
    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testFetchPendingTransaction_shouldReturnTransactionList(): Unit = runBlocking {
        // Use future timestamps to avoid expiration (ISO-8601 format for kotlinx.serialization)
        val now = kotlin.time.Clock.System.now()
        val creationTime = now.toString()
        val expiryTime = now.plus(kotlin.time.Duration.parse("2m")).toString()
        
        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/verifications") -> {
                    respond(
                        content = """
                        {
                          "total": 1,
                          "verifications": [{
                            "id": "test-transaction-id-001",
                            "creationTime": "$creationTime",
                            "expiryTime": "$expiryTime",
                            "transactionData": "{\"message\":\"Verify your test configuration\",\"originIpAddress\":\"192.168.1.100\",\"originUserAgent\":\"Mozilla/5.0 (Test Browser)\"}",
                            "authenticationMethods": [{
                              "id": "87dbc69e-3e4a-4b33-9b89-6ecdaf3c8510",
                              "methodType": "signature",
                              "subType": "user_presence"
                            }]
                          }]
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                            HttpHeaders.CacheControl to listOf("no-cache, no-store, max-age=0, must-revalidate")
                        )
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        }

        val httpClient = HttpClient(mockEngine)
        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/test-authenticator-id/verifications"),
            _authenticatorId = "test-authenticator-id",
            httpClient = httpClient
        )

        val result = service.nextTransaction()

        result.onFailure { error ->
            throw AssertionError("Fetch pending transaction failed: ${error.message}", error)
        }
        
        assertTrue("Fetch pending transaction should succeed", result.isSuccess)
        result.onSuccess { (transactions, count) ->
            assertEquals(1, count)
            assertEquals(1, transactions.size)
            
            val transaction = transactions.first()
            assertEquals("test-transaction-id-001", transaction.id)
            assertEquals("Verify your test configuration", transaction.message)
            
            // Verify transaction attributes
            val attributes = transaction.additionalData
            assertNotNull("Transaction attributes should not be null", attributes)
            assertTrue("Should contain IP address", attributes.containsKey(TransactionAttribute.IPAddress))
            assertTrue("Should contain user agent", attributes.containsKey(TransactionAttribute.UserAgent))
        }

        httpClient.close()
    }

    /**
     * Test Case 3: Complete Transaction with Signed Data
     * 
     * Based on log lines 535-566:
     * - POST to /v1.0/authenticators/{id}/verifications/{transactionId}
     * - Includes signed data and userAction=VERIFY_ATTEMPT
     * - Response is 204 No Content on success
     */
    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testCompleteTransaction_shouldReturn204(): Unit = runBlocking {
        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/verifications/test-transaction-id-001") -> {
                    respond(
                        content = "",
                        status = HttpStatusCode.NoContent,
                        headers = headersOf(
                            HttpHeaders.ContentLanguage, "en"
                        )
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        }

        val httpClient = HttpClient(mockEngine)
        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/test-authenticator-id/verifications"),
            _authenticatorId = "test-authenticator-id",
            httpClient = httpClient
        )

        // Use future timestamps to avoid expiration
        val now = kotlin.time.Clock.System.now()
        val expiryTime = now.plus(kotlin.time.Duration.parse("2m"))
        
        // Create mock transaction using actual PendingTransactionInfo structure
        val mockTransaction = com.ibm.security.verifysdk.mfa.PendingTransactionInfo(
            id = "test-transaction-id-001",
            message = "Verify your test configuration",
            postbackUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/test-auth-id/verifications/test-transaction-id-001"),
            factorID = java.util.UUID.fromString("87dbc69e-3e4a-4b33-9b89-6ecdaf3c8510"),
            factorType = "signature",
            dataToSign = "test_data_to_sign",
            creationTime = now,
            expiryTime = expiryTime,
            additionalData = mapOf(
                TransactionAttribute.IPAddress to "192.168.1.100",
                TransactionAttribute.UserAgent to "Mozilla/5.0"
            )
        )

        val result = service.completeTransaction(
            transaction = mockTransaction,
            userAction = UserAction.VERIFY,
            signedData = "test_signed_data_sanitized"
        )

        result.onFailure { error ->
            throw AssertionError("Complete transaction failed: ${error.message}", error)
        }
        
        assertTrue("Complete transaction should succeed", result.isSuccess)

        httpClient.close()
    }

    /**
     * Test Case 4: Empty Transaction List
     * 
     * Validates handling when no pending transactions exist.
     */
    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testFetchPendingTransaction_whenNoPending_shouldReturnEmptyList(): Unit = runBlocking {
        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/verifications") -> {
                    respond(
                        content = """
                        {
                          "total": 0,
                          "count": 0,
                          "verifications": []
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        }

        val httpClient = HttpClient(mockEngine)
        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/test-authenticator-id/verifications"),
            _authenticatorId = "test-authenticator-id",
            httpClient = httpClient
        )

        val result = service.nextTransaction()

        assertTrue("Fetch should succeed even with no transactions", result.isSuccess)
        result.onSuccess { (transactions, count) ->
            assertTrue("Transaction list should be empty", transactions.isEmpty())
            assertEquals(0, count)
        }

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testFetchPendingTransaction_withMultipleTransactions_shouldReturnAllForAuthenticator(): Unit = runBlocking {
        val now = kotlin.time.Clock.System.now()
        val creationTime = now.toString()
        val expiryTime = now.plus(kotlin.time.Duration.parse("2m")).toString()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/verifications") -> {
                    respond(
                        content = """
                        {
                          "total": 2,
                          "count": 2,
                          "verifications": [
                            {
                              "id": "11111111-aaaa-bbbb-cccc-000000000001",
                              "creationTime": "$creationTime",
                              "expiryTime": "$expiryTime",
                              "correlationEnabled": true,
                              "correlationValue": "13",
                              "transactionData": "{\"message\":\"Approve sign in for account A\",\"originIpAddress\":\"192.168.1.100\",\"originUserAgent\":\"Mozilla/5.0 (Account A Browser)\",\"additionalData\":[{\"name\":\"type\",\"value\":\"Sign in request\"},{\"name\":\"originLocation\",\"value\":\"Brisbane, AU\"},{\"name\":\"denyReasonEnabled\",\"value\":\"true\"},{\"name\":\"merchant\",\"value\":\"Account A\"}]}",
                              "authenticationMethods": [{
                                "id": "87dbc69e-3e4a-4b33-9b89-6ecdaf3c8510",
                                "methodType": "signature",
                                "subType": "user_presence"
                              }]
                            },
                            {
                              "id": "22222222-aaaa-bbbb-cccc-000000000002",
                              "creationTime": "$creationTime",
                              "expiryTime": "$expiryTime",
                              "transactionData": "{\"message\":\"Approve payment for account A\",\"originIpAddress\":\"192.168.1.101\",\"originUserAgent\":\"Mozilla/5.0 (Account A Payments)\",\"additionalData\":[{\"name\":\"type\",\"value\":\"Payment approval\"},{\"name\":\"imageURL\",\"value\":\"https://example.com/payment.png\"},{\"name\":\"merchant\",\"value\":\"Account A Payments\"}]}",
                              "authenticationMethods": [{
                                "id": "97dbc69e-3e4a-4b33-9b89-6ecdaf3c8511",
                                "methodType": "signature",
                                "subType": "user_presence"
                              }]
                            }
                          ]
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        }

        val httpClient = HttpClient(mockEngine)
        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/test-authenticator-id/verifications"),
            _authenticatorId = "test-authenticator-id",
            httpClient = httpClient
        )

        val result = service.nextTransaction()

        assertTrue("Fetch pending transaction should succeed", result.isSuccess)
        result.onSuccess { (transactions, count) ->
            assertEquals(2, count)
            assertEquals(2, transactions.size)

            val firstTransaction = transactions[0]
            assertEquals("11111111-aaaa-bbbb-cccc-000000000001", firstTransaction.id)
            assertEquals("Approve sign in for account A", firstTransaction.message)
            assertEquals("13", firstTransaction.additionalData[TransactionAttribute.Correlation])
            assertEquals("true", firstTransaction.additionalData[TransactionAttribute.DenyReason])
            assertEquals("Brisbane, AU", firstTransaction.additionalData[TransactionAttribute.Location])
            assertEquals("Sign in request", firstTransaction.additionalData[TransactionAttribute.Type])
            assertTrue(
                "First transaction should preserve custom attributes",
                firstTransaction.additionalData[TransactionAttribute.Custom]?.contains("merchant") == true
            )

            val secondTransaction = transactions[1]
            assertEquals("22222222-aaaa-bbbb-cccc-000000000002", secondTransaction.id)
            assertEquals("Approve payment for account A", secondTransaction.message)
            assertEquals("Payment approval", secondTransaction.additionalData[TransactionAttribute.Type])
            assertEquals("https://example.com/payment.png", secondTransaction.additionalData[TransactionAttribute.Image])
            assertTrue(
                "Second transaction should preserve custom attributes",
                secondTransaction.additionalData[TransactionAttribute.Custom]?.contains("Account A Payments") == true
            )
        }

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testFetchPendingTransaction_byIdentifier_shouldReturnOnlyRequestedTransaction(): Unit = runBlocking {
        val now = kotlin.time.Clock.System.now()
        val creationTime = now.toString()
        val expiryTime = now.plus(kotlin.time.Duration.parse("2m")).toString()
        var requestedUrl: String? = null

        val mockEngine = MockEngine { request ->
            requestedUrl = request.url.toString()
            when {
                request.url.encodedPath.contains("/verifications") -> {
                    respond(
                        content = """
                        {
                          "total": 1,
                          "count": 1,
                          "verifications": [{
                            "id": "22222222-aaaa-bbbb-cccc-000000000002",
                            "creationTime": "$creationTime",
                            "expiryTime": "$expiryTime",
                            "transactionData": "{\"message\":\"Approve payment for account A\",\"originIpAddress\":\"192.168.1.101\",\"originUserAgent\":\"Mozilla/5.0 (Account A Payments)\"}",
                            "authenticationMethods": [{
                              "id": "97dbc69e-3e4a-4b33-9b89-6ecdaf3c8511",
                              "methodType": "signature",
                              "subType": "user_presence"
                            }]
                          }]
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        }

        val httpClient = HttpClient(mockEngine)
        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/test-authenticator-id/verifications"),
            _authenticatorId = "test-authenticator-id",
            httpClient = httpClient
        )

        val result = service.nextTransaction("22222222-aaaa-bbbb-cccc-000000000002")

        assertTrue("Fetch by identifier should succeed", result.isSuccess)
        assertTrue(
            "Request URL should include the requested transaction identifier",
            requestedUrl?.contains("id=\"22222222-aaaa-bbbb-cccc-000000000002\"") == true
        )
        result.onSuccess { (transactions, count) ->
            assertEquals(1, count)
            assertEquals(1, transactions.size)
            assertEquals("22222222-aaaa-bbbb-cccc-000000000002", transactions.first().id)
        }

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testFetchPendingTransaction_shouldFilterExpiredTransactionsButKeepServerCount(): Unit = runBlocking {
        val now = kotlin.time.Clock.System.now()
        val creationTime = now.toString()
        val expiredTime = now.minus(kotlin.time.Duration.parse("1m")).toString()
        val validExpiryTime = now.plus(kotlin.time.Duration.parse("2m")).toString()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/verifications") -> {
                    respond(
                        content = """
                        {
                          "total": 2,
                          "count": 2,
                          "verifications": [
                            {
                              "id": "expired-transaction-id-001",
                              "creationTime": "$creationTime",
                              "expiryTime": "$expiredTime",
                              "transactionData": "{\"message\":\"Expired transaction\"}",
                              "authenticationMethods": [{
                                "id": "87dbc69e-3e4a-4b33-9b89-6ecdaf3c8510",
                                "methodType": "signature",
                                "subType": "user_presence"
                              }]
                            },
                            {
                              "id": "valid-transaction-id-002",
                              "creationTime": "$creationTime",
                              "expiryTime": "$validExpiryTime",
                              "transactionData": "{\"message\":\"Valid transaction\"}",
                              "authenticationMethods": [{
                                "id": "97dbc69e-3e4a-4b33-9b89-6ecdaf3c8511",
                                "methodType": "signature",
                                "subType": "user_presence"
                              }]
                            }
                          ]
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        }

        val httpClient = HttpClient(mockEngine)
        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://sdk.verify.ibm.com/v1.0/authenticators/test-authenticator-id/verifications"),
            _authenticatorId = "test-authenticator-id",
            httpClient = httpClient
        )

        val result = service.nextTransaction()

        assertTrue("Fetch should succeed", result.isSuccess)
        result.onSuccess { (transactions, count) ->
            assertEquals("Server count should remain unchanged", 2, count)
            assertEquals("Only non-expired transactions should be returned", 1, transactions.size)
            assertEquals("valid-transaction-id-002", transactions.first().id)
        }

        httpClient.close()
    }
}
