/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.mfa.MFARegistrationError
import com.ibm.security.verifysdk.mfa.RegistrationInitiation
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.content.TextContent
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import kotlin.test.assertFailsWith

/**
 * Instrumented tests for CloudRegistrationProvider, which will execute on an Android device.
 */
@RunWith(AndroidJUnit4::class)
class CloudRegistrationProviderTest {

    private val testInitiateUri = URL("https://example.com/v1.0/authenticators/initiation")
    private val testAccessToken = "test-access-token-12345"
    private val testClientId = "a8f0043d-acf5-4150-8622-bde8690dce7d"
    private val testAccountName = "Test Account"

    private val successResponseJson = """
        {
            "code": "ABC123XYZ",
            "uri": "https://example.com/v1.0/authenticators/registration",
            "accountName": "Test Account"
        }
    """.trimIndent()

    /**
     * Test successful registration initiation with valid parameters.
     */
    @Test
    fun testInAppInitiate_Success() = runTest {
        // Create mock HTTP client that returns success response
        val mockEngine = MockEngine { request ->
            // Verify request method and URL
            assertEquals("https://example.com/v1.0/authenticators/initiation", request.url.toString())
            assertEquals(io.ktor.http.HttpMethod.Post, request.method)

            // Verify headers
            assertTrue(request.headers[HttpHeaders.Authorization]?.startsWith("Bearer ") == true)
            assertEquals(ContentType.Application.Json.toString(), request.body.contentType?.toString())
            assertEquals(ContentType.Application.Json.toString(), request.headers[HttpHeaders.Accept])

            respond(
                content = successResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        // Execute the function
        val result = CloudRegistrationProvider.inAppInitiate(
            initiateUri = testInitiateUri,
            accessToken = testAccessToken,
            clientId = testClientId,
            accountName = testAccountName,
            httpClient = httpClient
        )

        // Verify the result
        assertNotNull(result)
        assertTrue(result.contains("code"))
        assertTrue(result.contains("ABC123XYZ"))
        assertTrue(result.contains("uri"))
        assertTrue(result.contains("accountName"))
    }

    /**
     * Test that the request body contains correct clientId and accountName.
     */
    @Test
    fun testInAppInitiate_RequestBodyContainsCorrectData() = runTest {
        var capturedRequestBody: String? = null

        val mockEngine = MockEngine { request ->
            // Capture the request body - need to cast to TextContent to get the text
            capturedRequestBody = (request.body as? TextContent)?.text

            respond(
                content = successResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        CloudRegistrationProvider.inAppInitiate(
            initiateUri = testInitiateUri,
            accessToken = testAccessToken,
            clientId = testClientId,
            accountName = testAccountName,
            httpClient = httpClient
        )

        // Verify request body contains expected fields
        assertNotNull(capturedRequestBody)
        assertTrue(capturedRequestBody!!.contains("clientId"))
        assertTrue(capturedRequestBody!!.contains(testClientId))
        assertTrue(capturedRequestBody!!.contains("accountName"))
        assertTrue(capturedRequestBody!!.contains(testAccountName))
    }

    /**
     * Test that authorization header is correctly set with Bearer token.
     */
    @Test
    fun testInAppInitiate_AuthorizationHeaderIsSet() = runTest {
        var capturedAuthHeader: String? = null

        val mockEngine = MockEngine { request ->
            capturedAuthHeader = request.headers[HttpHeaders.Authorization]

            respond(
                content = successResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        CloudRegistrationProvider.inAppInitiate(
            initiateUri = testInitiateUri,
            accessToken = testAccessToken,
            clientId = testClientId,
            accountName = testAccountName,
            httpClient = httpClient
        )

        // Verify authorization header
        assertNotNull(capturedAuthHeader)
        assertEquals("Bearer $testAccessToken", capturedAuthHeader)
    }

    /**
     * Test failure when server returns empty response body.
     */
    @Test
    fun testInAppInitiate_EmptyResponseThrowsError() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = "",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        assertFailsWith<MFARegistrationError.DataInitializationFailed> {
            CloudRegistrationProvider.inAppInitiate(
                initiateUri = testInitiateUri,
                accessToken = testAccessToken,
                clientId = testClientId,
                accountName = testAccountName,
                httpClient = httpClient
            )
        }
    }

    /**
     * Test failure when server returns 400 Bad Request.
     */
    @Test
    fun testInAppInitiate_BadRequestThrowsError() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = """{"error": "Invalid request"}""",
                status = HttpStatusCode.BadRequest,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        assertFailsWith<MFARegistrationError.FailedToParse> {
            CloudRegistrationProvider.inAppInitiate(
                initiateUri = testInitiateUri,
                accessToken = testAccessToken,
                clientId = testClientId,
                accountName = testAccountName,
                httpClient = httpClient
            )
        }
    }

    /**
     * Test failure when server returns 401 Unauthorized.
     */
    @Test
    fun testInAppInitiate_UnauthorizedThrowsError() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = """{"error": "Unauthorized"}""",
                status = HttpStatusCode.Unauthorized,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        assertFailsWith<MFARegistrationError.FailedToParse> {
            CloudRegistrationProvider.inAppInitiate(
                initiateUri = testInitiateUri,
                accessToken = testAccessToken,
                clientId = testClientId,
                accountName = testAccountName,
                httpClient = httpClient
            )
        }
    }

    /**
     * Test failure when server returns 500 Internal Server Error.
     */
    @Test
    fun testInAppInitiate_ServerErrorThrowsError() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                content = """{"error": "Internal server error"}""",
                status = HttpStatusCode.InternalServerError,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(
                    Json {
                        ignoreUnknownKeys = true
                        encodeDefaults = true
                    }
                )
            }
        }

        assertFailsWith<MFARegistrationError.FailedToParse> {
            CloudRegistrationProvider.inAppInitiate(
                initiateUri = testInitiateUri,
                accessToken = testAccessToken,
                clientId = testClientId,
                accountName = testAccountName,
                httpClient = httpClient
            )
        }
    }

    /**
     * Test that content type headers are correctly set.
     */
    @Test
    fun testInAppInitiate_ContentTypeHeadersAreSet() = runTest {
        var capturedAccept: String? = null
        var capturedBodyContentType: String? = null

        val mockEngine = MockEngine { request ->
            capturedAccept = request.headers[HttpHeaders.Accept]
            // Content-Type may be set on the body content rather than headers
            capturedBodyContentType = request.body.contentType?.toString()

            respond(
                content = successResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        CloudRegistrationProvider.inAppInitiate(
            initiateUri = testInitiateUri,
            accessToken = testAccessToken,
            clientId = testClientId,
            accountName = testAccountName,
            httpClient = httpClient
        )

        // Verify headers
        assertEquals(ContentType.Application.Json.toString(), capturedAccept)
        // Verify body content type is set
        assertNotNull(capturedBodyContentType)
        assertTrue(capturedBodyContentType!!.contains("application/json"))
    }

    /**
     * Test with different account names including special characters.
     */
    @Test
    fun testInAppInitiate_WithSpecialCharactersInAccountName() = runTest {
        val specialAccountName = "Test Account @#$%^&*()"

        val mockEngine = MockEngine { request ->
            respond(
                content = successResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        val result = CloudRegistrationProvider.inAppInitiate(
            initiateUri = testInitiateUri,
            accessToken = testAccessToken,
            clientId = testClientId,
            accountName = specialAccountName,
            httpClient = httpClient
        )

        assertNotNull(result)
    }

    /**
     * Test return type is RegistrationInitiation (String alias).
     */
    @Test
    fun testInAppInitiate_ReturnsRegistrationInitiationType() = runTest {
        val mockEngine = MockEngine { request ->
            respond(
                content = successResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        val result: RegistrationInitiation = CloudRegistrationProvider.inAppInitiate(
            initiateUri = testInitiateUri,
            accessToken = testAccessToken,
            clientId = testClientId,
            accountName = testAccountName,
            httpClient = httpClient
        )

        // Verify result is a String (RegistrationInitiation is a typealias for String)
        assertTrue(result is String)
        assertNotNull(result)
    }
}
