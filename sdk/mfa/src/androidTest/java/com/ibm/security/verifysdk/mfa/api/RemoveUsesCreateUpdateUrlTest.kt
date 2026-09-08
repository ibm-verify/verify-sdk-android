/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.mfa.MFAServiceException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

/**
 * Integration tests for [OnPremiseAuthenticatorService.remove].
 *
 * Verifies that [remove] uses the URL produced by the private [createUpdateUrl] helper:
 * - scheme + authority + path taken from the constructor's [_transactionUri]
 * - fixed `attributes=…MMFA:Authenticator:authenticators` query parameter appended
 * - no double-slash between host and path
 */
@RunWith(AndroidJUnit4::class)
class RemoveUsesCreateUpdateUrlTest {

    @Before
    fun setup() {
        ContextHelper.init(InstrumentationRegistry.getInstrumentation().targetContext)
    }

    @Test
    fun testRemove_sendsRequestToUpdateUrl() = runTest {
        var capturedUrl: String? = null

        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_token",
            _refreshUri = URL("https://example.com/refresh"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "client",
            _authenticatorId = "auth-id",
            httpClient = HttpClient(MockEngine { request ->
                capturedUrl = request.url.toString()
                respond("", HttpStatusCode.OK)
            })
        )

        service.remove()

        assertNotNull("PATCH request must have been sent", capturedUrl)
        val url = capturedUrl!!
        assertTrue(
            "Request URL must start with https://example.com/scim/Me",
            url.startsWith("https://example.com/scim/Me")
        )
        assertTrue(
            "Request URL must contain the attributes query parameter",
            url.contains("attributes=")
        )
        assertTrue(
            "Request URL must contain the Authenticator SCIM URN",
            url.contains("MMFA%3AAuthenticator%3Aauthenticators")
        )
        assertFalse(
            "Request URL must not contain a double-slash after the host",
            url.substring("https://".length).contains("//")
        )
    }

    @Test
    fun testRemove_withCustomPort_preservesPortInRequestUrl() = runTest {
        var capturedUrl: String? = null

        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_token",
            _refreshUri = URL("https://onprem.local:9443/refresh"),
            _transactionUri = URL("https://onprem.local:9443/scim/Me"),
            _clientId = "client",
            _authenticatorId = "auth-id",
            httpClient = HttpClient(MockEngine { request ->
                capturedUrl = request.url.toString()
                respond("", HttpStatusCode.OK)
            })
        )

        service.remove()

        assertNotNull("PATCH request must have been sent", capturedUrl)
        val url = capturedUrl!!
        assertTrue("Request URL must include the custom port", url.contains(":9443"))
        assertTrue(
            "Request URL must contain the attributes query parameter",
            url.contains("attributes=")
        )
    }

    @Test
    fun testRemove_withDeepTransactionUri_preservesPath() = runTest {
        var capturedUrl: String? = null

        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_token",
            _refreshUri = URL("https://example.com/refresh"),
            _transactionUri = URL("https://example.com/mga/scim/v2/Me"),
            _clientId = "client",
            _authenticatorId = "auth-id",
            httpClient = HttpClient(MockEngine { request ->
                capturedUrl = request.url.toString()
                respond("", HttpStatusCode.OK)
            })
        )

        service.remove()

        assertNotNull("PATCH request must have been sent", capturedUrl)
        val url = capturedUrl!!
        assertTrue(
            "Request URL must contain the full transactionUri path",
            url.contains("/mga/scim/v2/Me")
        )
        assertFalse(
            "Request URL must not contain a double-slash after the host",
            url.substring("https://".length).contains("//")
        )
    }

    @Test
    fun testRemove_serverError_returnsFailure() = runTest {
        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_token",
            _refreshUri = URL("https://example.com/refresh"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "client",
            _authenticatorId = "auth-id",
            httpClient = HttpClient(MockEngine {
                respond(
                    "Internal Server Error",
                    HttpStatusCode.InternalServerError
                )
            })
        )

        val result = service.remove()

        assertTrue("Non-2xx response must produce a failure result", result.isFailure)
    }

    @Test
    fun testRemove_emptyErrorBody_returnsInvalidDataResponse() = runTest {
        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_token",
            _refreshUri = URL("https://example.com/refresh"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "client",
            _authenticatorId = "auth-id",
            httpClient = HttpClient(MockEngine { respond("", HttpStatusCode.InternalServerError) })
        )

        val result = service.remove()

        assertTrue("Empty-body error must produce a failure result", result.isFailure)
        assertTrue(
            "Failure must be MFAServiceException.InvalidDataResponse",
            result.exceptionOrNull() is MFAServiceException.InvalidDataResponse
        )
    }
}
