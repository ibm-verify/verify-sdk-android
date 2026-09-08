/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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

    @Test
    fun testHttpClientConstructorInjection() = runTest {
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

            // refreshToken no longer takes httpClient as parameter
            val result = service.refreshToken(
                refreshToken = "test_refresh_token",
                accountName = "test@example.com",
                pushToken = "test_push_token",
                additionalData = null
            )

            assertTrue("refreshToken should succeed", result.isSuccess)
        httpClient.close()
    }

    @Test
    fun testTokenPersistenceCallbackBlocking() = runTest {
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
        httpClient.close()
    }

    @Test
    fun testTokenPersistenceFailureCausesRefreshFailure() = runTest {
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
        httpClient.close()
    }

    @Test
    fun refreshToken_cancellationDuringRequest_shouldRethrowCancellationException() = runTest {
        val requestStarted = CompletableDeferred<Unit>()
        val engine = MockEngine {
            requestStarted.complete(Unit)
            awaitCancellation()
        }
        val client = HttpClient(engine)
        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = client
        )
        var result: Result<TokenInfo>? = null
        var cancellation: CancellationException? = null

        val job = launch {
            try {
                result = service.refreshToken("test_refresh_token", null, null, null)
            } catch (e: CancellationException) {
                cancellation = e
            }
        }

        requestStarted.await()
        job.cancel()
        job.join()
        client.close()

        assertNotNull("refreshToken must rethrow cancellation", cancellation)
        assertNull("refreshToken must not return a failure result for cancellation", result)
    }

    @Test
    fun refreshToken_cancellationFromPersistenceCallback_shouldRethrowCancellationException() = runTest {
        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                throw CancellationException("test persistence cancellation")
            }
        }
        val engine = MockEngine {
            respond(
                content = """{"access_token":"new_token","refresh_token":"new_refresh","token_type":"Bearer","expires_in":3600}""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }
        val client = HttpClient(engine)
        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = client,
            persistenceCallback = callback
        )
        var result: Result<TokenInfo>? = null
        var cancellation: CancellationException? = null

        try {
            result = service.refreshToken("test_refresh_token", null, null, null)
        } catch (e: CancellationException) {
            cancellation = e
        }
        client.close()

        assertNotNull("refreshToken must rethrow callback cancellation", cancellation)
        assertNull("refreshToken must not return a result for callback cancellation", result)
    }

    @Test
    fun testImmutableServiceDesign() = runTest {
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

            service.refreshToken(
                refreshToken = "test_refresh_token",
                accountName = "test@example.com",
                pushToken = "test_push_token",
                additionalData = null
            )

            // Service instance still has original token (immutable)
            assertEquals("original_token", service.accessToken)
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

    @Test
    fun testLoginSuccess() = runTest {
        // Verify successful QR code login
        val mockEngine = MockEngine { request ->
            // Verify request structure
            assertEquals("POST", request.method.value)
            assertTrue(request.url.toString().contains("/login"))
            assertTrue(request.headers["Authorization"]?.startsWith("Bearer ") == true)

            respond(
                content = "",
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
            httpClient = httpClient
        )

            val result = service.login(
                qrLoginEndpoint = "https://example.com/v1.0/authenticators/login",
                code = "abc123xyz"
            )

            assertTrue("Login should succeed", result.isSuccess)
        httpClient.close()
    }

    @Test
    fun testLoginUnauthorized() = runTest {
        // Verify 401 unauthorized response handling
        val mockEngine = MockEngine { request ->
            respond(
                content = """{"error":"invalid_token","error_description":"The access token is invalid or expired"}""",
                status = HttpStatusCode.Unauthorized,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = CloudAuthenticatorService(
            _accessToken = "invalid_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = httpClient
        )

            val result = service.login(
                qrLoginEndpoint = "https://example.com/v1.0/authenticators/login",
                code = "abc123xyz"
            )

            assertTrue("Login should fail with 401", result.isFailure)
            result.onFailure { error ->
                assertTrue(
                    "Error should be AuthorizationException",
                    error is com.ibm.security.verifysdk.core.AuthorizationException
                )
            }
        httpClient.close()
    }

    @Test
    fun testLoginInvalidCode() = runTest {
        // Verify handling of invalid login code
        val mockEngine = MockEngine { request ->
            respond(
                content = """{"error":"invalid_code","error_description":"The provided login code is invalid or expired"}""",
                status = HttpStatusCode.BadRequest,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = httpClient
        )

            val result = service.login(
                qrLoginEndpoint = "https://example.com/v1.0/authenticators/login",
                code = "invalid_code"
            )

            assertTrue("Login should fail with invalid code", result.isFailure)
            result.onFailure { error ->
                assertTrue(
                    "Error should be MFAServiceException",
                    error is com.ibm.security.verifysdk.mfa.MFAServiceException
                )
            }
        httpClient.close()
    }

    @Test
    fun testLoginNetworkError() = runTest {
        // Verify handling of network errors
        val mockEngine = MockEngine { request ->
            throw Exception("Network connection failed")
        }

        val httpClient = HttpClient(mockEngine)

        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id",
            httpClient = httpClient
        )

            val result = service.login(
                qrLoginEndpoint = "https://example.com/v1.0/authenticators/login",
                code = "abc123xyz"
            )

            assertTrue("Login should fail with network error", result.isFailure)
            result.onFailure { error ->
                assertTrue(
                    "Error should be MFAServiceException.General",
                    error is com.ibm.security.verifysdk.mfa.MFAServiceException.General
                )
                assertTrue(
                    "Error message should mention network failure",
                    error.message?.contains("Network connection failed") == true
                )
            }
        httpClient.close()
    }

    @Test
    fun testLoginRequestPayload() = runTest {
        // Verify that the request payload is correctly formatted
        var capturedRequestBody: String? = null

        val mockEngine = MockEngine { request ->
            capturedRequestBody = request.body.toString()

            respond(
                content = "",
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
            httpClient = httpClient
        )

            service.login(
                qrLoginEndpoint = "https://example.com/v1.0/authenticators/login",
                code = "test_code_123"
            )

            // Verify the request body contains the code
            assertTrue(
                "Request body should contain the code",
                capturedRequestBody?.contains("test_code_123") == true
            )
            assertTrue(
                "Request body should be JSON format",
                capturedRequestBody?.contains("\"code\"") == true
            )
        httpClient.close()
    }
}

