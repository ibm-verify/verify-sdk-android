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
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

/**
 * Test suite for CloudAuthenticatorService to verify:
 * 1. HttpClient constructor injection
 * 2. Token persistence callback (blocking)
 * 3. Immutable service design
 */
@RunWith(AndroidJUnit4::class)
class CloudAuthenticatorServiceTest {

    @Before
    fun setup() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        ContextHelper.init(appContext)
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testHttpClientConstructorInjection() {
        // Verify that httpClient is passed via constructor, not method parameter
        val mockEngine = MockEngine { request ->
            respond(
                content = """{"access_token":"new_token","refresh_token":"new_refresh","token_type":"Bearer","expires_in":3600}""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine)

        // HttpClient is now a constructor parameter
        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = httpClient  // Constructor parameter
        )

        runBlocking {
            // refreshToken no longer takes httpClient as parameter
            val result = service.refreshToken(
                refreshToken = "test_refresh_token",
                accountName = "test@example.com",
                pushToken = "test_push_token",
                additionalData = null
            )

            assertTrue("refreshToken should succeed", result.isSuccess)
        }

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testTokenPersistenceCallbackBlocking() {
        // Verify that token persistence callback is invoked and blocks
        var callbackInvoked = false
        var persistedToken: TokenInfo? = null

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                callbackInvoked = true
                persistedToken = newToken
                assertEquals("test_authenticator_id", authenticatorId)
                return Result.success(Unit)
            }
        }

        val mockEngine = MockEngine { request ->
            respond(
                content = """{"access_token":"persisted_token","refresh_token":"persisted_refresh","token_type":"Bearer","expires_in":3600}""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = httpClient,
            persistenceCallback = callback
        )

        runBlocking {
            val result = service.refreshToken(
                refreshToken = "test_refresh_token",
                accountName = "test@example.com",
                pushToken = "test_push_token",
                additionalData = null
            )

            assertTrue("refreshToken should succeed", result.isSuccess)
            assertTrue("Callback should be invoked", callbackInvoked)
            assertEquals("persisted_token", persistedToken?.accessToken)
            assertEquals("persisted_refresh", persistedToken?.refreshToken)
        }

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testTokenPersistenceFailureCausesRefreshFailure() {
        // Verify that if persistence fails, the entire refresh fails
        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                // Simulate persistence failure
                return Result.failure(Exception("Database write failed"))
            }
        }

        val mockEngine = MockEngine { request ->
            respond(
                content = """{"access_token":"new_token","refresh_token":"new_refresh","token_type":"Bearer","expires_in":3600}""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = httpClient,
            persistenceCallback = callback
        )

        runBlocking {
            val result = service.refreshToken(
                refreshToken = "test_refresh_token",
                accountName = "test@example.com",
                pushToken = "test_push_token",
                additionalData = null
            )

            // Refresh should fail because persistence failed
            assertTrue("refreshToken should fail when persistence fails", result.isFailure)
            result.onFailure { error ->
                assertTrue(
                    "Error message should mention persistence failure",
                    error.message?.contains("persistence failed") == true
                )
            }
        }

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testImmutableServiceDesign() {
        // Verify that service properties are immutable
        val mockEngine = MockEngine { request ->
            respond(
                content = """{"access_token":"new_token","refresh_token":"new_refresh","token_type":"Bearer","expires_in":3600}""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = CloudAuthenticatorService(
            _accessToken = "original_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = httpClient
        )

        // Access token should remain unchanged after refresh
        val originalToken = service.accessToken
        assertEquals("original_token", originalToken)

        runBlocking {
            service.refreshToken(
                refreshToken = "test_refresh_token",
                accountName = "test@example.com",
                pushToken = "test_push_token",
                additionalData = null
            )

            // Service instance still has original token (immutable)
            assertEquals("original_token", service.accessToken)
        }

        httpClient.close()
    }

    @Test
    fun testServicePropertiesAreAccessible() {
        // Verify that all service properties are accessible
        val mockEngine = MockEngine { request ->
            respond(
                content = "{}",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = CloudAuthenticatorService(
            _accessToken = "test_token",
            _refreshUri = URL("https://example.com/refresh"),
            _transactionUri = URL("https://example.com/transactions"),
            _authenticatorId = "test_id",
            httpClient = httpClient
        )

        assertEquals("test_token", service.accessToken)
        assertEquals("https://example.com/refresh", service.refreshUri.toString())
        assertEquals("https://example.com/transactions", service.transactionUri.toString())
        assertEquals("test_id", service.authenticatorId)

        httpClient.close()
    }
}

