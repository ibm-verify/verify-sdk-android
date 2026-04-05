/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds

/**
 * Comprehensive test suite for TokenPersistenceCallback interface.
 *
 * Tests verify:
 * 1. Successful token persistence
 * 2. Persistence failure handling
 * 3. Callback invocation with correct parameters
 * 4. Thread safety and concurrent access
 * 5. Performance characteristics (< 100ms recommended)
 * 6. Error propagation and exception handling
 * 7. Atomicity guarantees
 */
@RunWith(AndroidJUnit4::class)
class TokenPersistenceCallbackTest {

    /**
     * Test successful token persistence with valid data.
     */
    @Test
    fun testSuccessfulTokenPersistence(): Unit = runBlocking {
        var callbackInvoked = false
        var receivedAuthenticatorId: String? = null
        var receivedToken: TokenInfo? = null

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                callbackInvoked = true
                receivedAuthenticatorId = authenticatorId
                receivedToken = newToken
                return Result.success(Unit)
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_access_token",
            refreshToken = "test_refresh_token",
            tokenType = "Bearer",
            expiresIn = 3600,
            scope = "openid profile",
            additionalData = emptyMap()
        )

        val result = callback.onTokenRefreshed("test_authenticator_id", testToken)

        assertTrue("Callback should be invoked", callbackInvoked)
        assertEquals("test_authenticator_id", receivedAuthenticatorId)
        assertEquals("test_access_token", receivedToken?.accessToken)
        assertEquals("test_refresh_token", receivedToken?.refreshToken)
        assertTrue("Result should be success", result.isSuccess)
    }

    /**
     * Test persistence failure handling.
     */
    @Test
    fun testPersistenceFailure(): Unit = runBlocking {
        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                return Result.failure(Exception("Database write failed"))
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_access_token",
            refreshToken = "test_refresh_token",
            tokenType = "Bearer",
            expiresIn = 3600,
            additionalData = emptyMap()
        )

        val result = callback.onTokenRefreshed("test_authenticator_id", testToken)

        assertTrue("Result should be failure", result.isFailure)
        result.onFailure { error ->
            assertEquals("Database write failed", error.message)
        }
    }

    /**
     * Test that callback receives correct authenticator ID.
     */
    @Test
    fun testCorrectAuthenticatorIdPassed(): Unit = runBlocking {
        val expectedIds = listOf("auth_1", "auth_2", "auth_3")
        val receivedIds = mutableListOf<String>()

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                receivedIds.add(authenticatorId)
                return Result.success(Unit)
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_token",
            refreshToken = "test_refresh",
            tokenType = "Bearer",
            expiresIn = 3600,
            additionalData = emptyMap()
        )

        expectedIds.forEach { id ->
            callback.onTokenRefreshed(id, testToken)
        }

        assertEquals("All authenticator IDs should be received", expectedIds, receivedIds)
    }

    /**
     * Test that callback receives complete token information.
     */
    @Test
    fun testCompleteTokenInformationPassed(): Unit = runBlocking {
        var receivedToken: TokenInfo? = null

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                receivedToken = newToken
                return Result.success(Unit)
            }
        }

        val testToken = TokenInfo(
            accessToken = "access_123",
            refreshToken = "refresh_456",
            tokenType = "Bearer",
            expiresIn = 7200,
            scope = "openid profile email",
            idToken = "id_token_789",
            additionalData = emptyMap()
        )

        callback.onTokenRefreshed("test_id", testToken)

        assertNotNull("Token should be received", receivedToken)
        assertEquals("access_123", receivedToken?.accessToken)
        assertEquals("refresh_456", receivedToken?.refreshToken)
        assertEquals("Bearer", receivedToken?.tokenType)
        assertEquals(7200, receivedToken?.expiresIn)
        assertEquals("openid profile email", receivedToken?.scope)
        assertEquals("id_token_789", receivedToken?.idToken)
    }

    /**
     * Test exception handling in callback.
     */
    @Test
    fun testExceptionHandling(): Unit = runBlocking {
        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                return try {
                    throw IllegalStateException("Simulated database error")
                } catch (e: Exception) {
                    Result.failure(e)
                }
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_token",
            refreshToken = "test_refresh",
            tokenType = "Bearer",
            expiresIn = 3600,
            additionalData = emptyMap()
        )

        val result = callback.onTokenRefreshed("test_id", testToken)

        assertTrue("Result should be failure", result.isFailure)
        result.onFailure { error ->
            assertTrue(error is IllegalStateException)
            assertEquals("Simulated database error", error.message)
        }
    }

    /**
     * Test callback performance (should complete in < 100ms).
     */
    @Test
    fun testCallbackPerformance(): Unit = runBlocking {
        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                // Simulate fast database write
                delay(50)
                return Result.success(Unit)
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_token",
            refreshToken = "test_refresh",
            tokenType = "Bearer",
            expiresIn = 3600,
            additionalData = emptyMap()
        )

        val startTime = System.currentTimeMillis()
        callback.onTokenRefreshed("test_id", testToken)
        val duration = System.currentTimeMillis() - startTime

        assertTrue(
            "Callback should complete in < 100ms (actual: ${duration}ms)",
            duration < 100
        )
    }

    /**
     * Test callback with slow persistence (warning case).
     */
    @Test
    fun testSlowPersistenceWarning(): Unit = runBlocking {
        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                // Simulate slow database write
                delay(150)
                return Result.success(Unit)
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_token",
            refreshToken = "test_refresh",
            tokenType = "Bearer",
            expiresIn = 3600,
            additionalData = emptyMap()
        )

        val startTime = System.currentTimeMillis()
        val result = callback.onTokenRefreshed("test_id", testToken)
        val duration = System.currentTimeMillis() - startTime

        assertTrue("Result should still succeed", result.isSuccess)
        assertTrue(
            "Slow persistence detected (${duration}ms), should be < 100ms",
            duration >= 100
        )
    }

    /**
     * Test thread safety with concurrent callback invocations.
     */
    @Test
    fun testThreadSafety(): Unit = runBlocking {
        val invocationCount = AtomicInteger(0)
        val successCount = AtomicInteger(0)

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                invocationCount.incrementAndGet()
                delay(10) // Simulate database operation
                successCount.incrementAndGet()
                return Result.success(Unit)
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_token",
            refreshToken = "test_refresh",
            tokenType = "Bearer",
            expiresIn = 3600,
            additionalData = emptyMap()
        )

        // Simulate concurrent invocations
        val jobs = List(10) { index ->
            launch {
                callback.onTokenRefreshed("auth_$index", testToken)
            }
        }

        jobs.forEach { it.join() }

        assertEquals("All invocations should complete", 10, invocationCount.get())
        assertEquals("All should succeed", 10, successCount.get())
    }

    /**
     * Test callback with null optional fields in TokenInfo.
     */
    @Test
    fun testTokenWithNullOptionalFields(): Unit = runBlocking {
        var receivedToken: TokenInfo? = null

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                receivedToken = newToken
                return Result.success(Unit)
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_token",
            refreshToken = "test_refresh",
            tokenType = "Bearer",
            expiresIn = 3600,
            scope = "",
            idToken = null,
            additionalData = emptyMap()
        )

        val result = callback.onTokenRefreshed("test_id", testToken)

        assertTrue("Result should be success", result.isSuccess)
        assertNotNull("Token should be received", receivedToken)
        assertEquals("Scope should be empty", "", receivedToken?.scope)
        assertNull("ID token should be null", receivedToken?.idToken)
    }

    /**
     * Test callback invocation order (FIFO).
     */
    @Test
    fun testCallbackInvocationOrder(): Unit = runBlocking {
        val invocationOrder = mutableListOf<String>()

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                invocationOrder.add(authenticatorId)
                return Result.success(Unit)
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_token",
            refreshToken = "test_refresh",
            tokenType = "Bearer",
            expiresIn = 3600,
            additionalData = emptyMap()
        )

        val expectedOrder = listOf("first", "second", "third")
        expectedOrder.forEach { id ->
            callback.onTokenRefreshed(id, testToken)
        }

        assertEquals("Invocation order should be preserved", expectedOrder, invocationOrder)
    }

    /**
     * Test callback with empty authenticator ID (edge case).
     */
    @Test
    fun testEmptyAuthenticatorId(): Unit = runBlocking {
        var receivedId: String? = null

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                receivedId = authenticatorId
                return if (authenticatorId.isEmpty()) {
                    Result.failure(Exception("Authenticator ID cannot be empty"))
                } else {
                    Result.success(Unit)
                }
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_token",
            refreshToken = "test_refresh",
            tokenType = "Bearer",
            expiresIn = 3600,
            additionalData = emptyMap()
        )

        val result = callback.onTokenRefreshed("", testToken)

        assertEquals("", receivedId)
        assertTrue("Result should be failure for empty ID", result.isFailure)
    }

    /**
     * Test callback atomicity guarantee.
     */
    @Test
    fun testAtomicityGuarantee(): Unit = runBlocking {
        val persistenceAttempted = AtomicBoolean(false)
        val persistenceCompleted = AtomicBoolean(false)

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                persistenceAttempted.set(true)
                
                // Simulate atomic database transaction
                return try {
                    delay(10) // Simulate write
                    persistenceCompleted.set(true)
                    Result.success(Unit)
                } catch (e: Exception) {
                    // Rollback would happen here
                    persistenceCompleted.set(false)
                    Result.failure(e)
                }
            }
        }

        val testToken = TokenInfo(
            accessToken = "test_token",
            refreshToken = "test_refresh",
            tokenType = "Bearer",
            expiresIn = 3600,
            additionalData = emptyMap()
        )

        val result = callback.onTokenRefreshed("test_id", testToken)

        assertTrue("Persistence should be attempted", persistenceAttempted.get())
        assertTrue("Persistence should complete", persistenceCompleted.get())
        assertTrue("Result should be success", result.isSuccess)
    }

    /**
     * Test callback with multiple token refreshes for same authenticator.
     */
    @Test
    fun testMultipleRefreshesForSameAuthenticator(): Unit = runBlocking {
        val tokens = mutableListOf<TokenInfo>()

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                tokens.add(newToken)
                return Result.success(Unit)
            }
        }

        val authenticatorId = "same_authenticator"
        
        // Simulate multiple refreshes
        repeat(3) { index ->
            val token = TokenInfo(
                accessToken = "token_$index",
                refreshToken = "refresh_$index",
                tokenType = "Bearer",
                expiresIn = 3600,
                additionalData = emptyMap()
            )
            callback.onTokenRefreshed(authenticatorId, token)
        }

        assertEquals("Should have 3 tokens", 3, tokens.size)
        assertEquals("token_0", tokens[0].accessToken)
        assertEquals("token_1", tokens[1].accessToken)
        assertEquals("token_2", tokens[2].accessToken)
    }
}
