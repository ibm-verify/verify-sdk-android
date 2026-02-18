/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.mfa.EnrollableSignature
import com.ibm.security.verifysdk.mfa.EnrollableType
import com.ibm.security.verifysdk.mfa.HashAlgorithmType
import com.ibm.security.verifysdk.mfa.MFARegistrationException
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
import org.junit.Before
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

    @Before
    fun setUp() {
        ContextHelper.init(InstrumentationRegistry.getInstrumentation().targetContext)
    }

    /**
     * Test successful registration initiation with valid parameters.
     */
    @Test
    fun testInAppInitiate_Success() = runTest {
        // Create mock HTTP client that returns success response
        val mockEngine = MockEngine { request ->
            // Verify request method and URL
            assertEquals(
                "https://example.com/v1.0/authenticators/initiation",
                request.url.toString()
            )
            assertEquals(io.ktor.http.HttpMethod.Post, request.method)

            // Verify headers
            assertTrue(request.headers[HttpHeaders.Authorization]?.startsWith("Bearer ") == true)
            assertEquals(
                ContentType.Application.Json.toString(),
                request.body.contentType?.toString()
            )
            assertEquals(
                ContentType.Application.Json.toString(),
                request.headers[HttpHeaders.Accept]
            )

            respond(
                content = successResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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
        assertTrue(capturedRequestBody?.contains("clientId") == true)
        assertTrue(capturedRequestBody?.contains(testClientId) == true)
        assertTrue(capturedRequestBody?.contains("accountName") == true)
        assertTrue(capturedRequestBody?.contains(testAccountName) == true)
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
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        assertFailsWith<MFARegistrationException.DataInitializationFailed> {
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
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        assertFailsWith<MFARegistrationException.FailedToParse> {
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
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        assertFailsWith<MFARegistrationException.FailedToParse> {
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
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        assertFailsWith<MFARegistrationException.FailedToParse> {
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
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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
        assertTrue(capturedBodyContentType?.contains("application/json") == true)
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
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

    /**
     * Test successful initiate() call with valid registration data.
     */
    @Test
    fun testInitiate_Success() = runTest {
        // Given - initialization data
        val initData = """
            {
                "code": "test-code-123",
                "accountName": "test@example.com",
                "registrationUri": "https://example.com/v1.0/authenticators/registration",
                "version": {
                    "number": "1.0.0",
                    "platform": "com.ibm.security.access.verify"
                }
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {
                        "totp": {
                            "enrollmentUri": "https://example.com/v2.0/factors/totp",
                            "enabled": true
                        },
                        "signature_fingerprint": {
                            "enrollmentUri": "https://example.com/v1.0/authnmethods/signatures",
                            "attributes": {
                                "algorithm": "RSASHA256"
                            },
                            "enabled": true
                        },
                        "signature_userPresence": {
                            "enrollmentUri": "https://example.com/v1.0/authnmethods/signatures",
                            "attributes": {
                                "algorithm": "RSASHA256"
                            },
                            "enabled": true
                        }
                    },
                    "registrationUri": "https://example.com/v1.0/authenticators/registration",
                    "serviceName": "Test Service"
                },
                "id": "test-authenticator-id-123",
                "accessToken": "test-access-token",
                "version": {
                    "number": "1.0.0",
                    "platform": "com.ibm.security.access.verify"
                },
                "refreshToken": "test-refresh-token"
            }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            // Verify URL contains skipTotpEnrollment parameter
            assertTrue(request.url.toString().contains("skipTotpEnrollment=true"))
            assertEquals(io.ktor.http.HttpMethod.Post, request.method)

            respond(
                content = registrationResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        // When
        val provider = CloudRegistrationProvider(initData)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "test-push-token",
            httpClient = httpClient
        )

        // Then
        assertTrue(result.isSuccess)
        val data = result.getOrNull()
        assertNotNull(data)
        assertNotNull(data?.tokenInfo)
        assertNotNull(data?.metadata)
        assertEquals("test-access-token", data?.tokenInfo?.accessToken)
        assertEquals("test-refresh-token", data?.tokenInfo?.refreshToken)
        assertEquals("Test Service", data?.metadata?.serviceName)
    }

    /**
     * Test initiate() with null pushToken.
     */
    @Test
    fun testInitiate_WithNullPushToken() = runTest {
        val initData = """
            {
                "code": "test-code-123",
                "accountName": "test@example.com",
                "registrationUri": "https://example.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "com.ibm.security.access.verify"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {},
                    "registrationUri": "https://example.com/v1.0/authenticators/registration",
                    "serviceName": "Test Service"
                },
                "id": "test-id",
                "accessToken": "token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "refresh"
            }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            respond(
                content = registrationResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        val provider = CloudRegistrationProvider(initData)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = null,
            httpClient = httpClient
        )

        assertTrue(result.isSuccess)
    }

    /**
     * Test initiate() request body contains code and attributes.
     */
    @Test
    fun testInitiate_RequestBodyContainsCodeAndAttributes() = runTest {
        val initData = """
            {
                "code": "ABC123XYZ",
                "accountName": "test@example.com",
                "registrationUri": "https://example.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {},
                    "registrationUri": "https://example.com/v1.0/authenticators/registration",
                    "serviceName": "Test"
                },
                "id": "id",
                "accessToken": "token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "refresh"
            }
        """.trimIndent()

        var capturedRequestBody: String? = null

        val mockEngine = MockEngine { request ->
            capturedRequestBody = (request.body as? TextContent)?.text

            respond(
                content = registrationResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        val provider = CloudRegistrationProvider(initData)
        provider.initiate(
            accountName = "test@example.com",
            pushToken = "push-token-123",
            httpClient = httpClient
        )

        assertNotNull(capturedRequestBody)
        assertTrue(capturedRequestBody?.contains("code") == true)
        assertTrue(capturedRequestBody?.contains("ABC123XYZ") == true)
        assertTrue(capturedRequestBody?.contains("attributes") == true)
        assertTrue(capturedRequestBody?.contains("accountName") == true)
        assertTrue(capturedRequestBody?.contains("pushToken") == true)
    }

    /**
     * Test initiate() failure with server error.
     */
    @Test
    fun testInitiate_ServerErrorReturnsFailure() = runTest {
        val initData = """
            {
                "code": "test-code",
                "accountName": "test@example.com",
                "registrationUri": "https://example.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            respond(
                content = """{"error": "Internal server error"}""",
                status = HttpStatusCode.InternalServerError,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        val provider = CloudRegistrationProvider(initData)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "token",
            httpClient = httpClient
        )

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull() is MFARegistrationException.General)
    }

    /**
     * Test initiate() with different account names.
     */
    @Test
    fun testInitiate_WithDifferentAccountNames() = runTest {
        val initData = """
            {
                "code": "code",
                "accountName": "original@example.com",
                "registrationUri": "https://example.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {},
                    "registrationUri": "https://example.com/v1.0/authenticators/registration",
                    "serviceName": "Test"
                },
                "id": "id",
                "accessToken": "token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "refresh"
            }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            respond(
                content = registrationResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        val provider = CloudRegistrationProvider(initData)
        val result = provider.initiate(
            accountName = "different@example.com",
            pushToken = "token",
            httpClient = httpClient
        )

        assertTrue(result.isSuccess)
        assertEquals("different@example.com", provider.accountName)
    }

    /**
     * Test initiate() URL construction with skipTotpEnrollment parameter.
     */
    @Test
    fun testInitiate_URLContainsSkipTotpEnrollmentParameter() = runTest {
        val initData = """
            {
                "code": "code",
                "accountName": "test@example.com",
                "registrationUri": "https://example.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {},
                    "registrationUri": "https://example.com/v1.0/authenticators/registration",
                    "serviceName": "Test"
                },
                "id": "id",
                "accessToken": "token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "refresh"
            }
        """.trimIndent()

        var capturedUrl: String? = null

        val mockEngine = MockEngine { request ->
            capturedUrl = request.url.toString()

            respond(
                content = registrationResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        val provider = CloudRegistrationProvider(initData)
        provider.initiate(
            accountName = "test@example.com",
            pushToken = "token",
            httpClient = httpClient
        )

        assertNotNull(capturedUrl)
        assertTrue(capturedUrl?.contains("skipTotpEnrollment=true") == true)
    }

    /**
     * Test initiate() sets pushToken property.
     */
    @Test
    fun testInitiate_SetsPushTokenProperty() = runTest {
        val initData = """
            {
                "code": "code",
                "accountName": "test@example.com",
                "registrationUri": "https://example.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {},
                    "registrationUri": "https://example.com/v1.0/authenticators/registration",
                    "serviceName": "Test"
                },
                "id": "id",
                "accessToken": "token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "refresh"
            }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            respond(
                content = registrationResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        val testPushToken = "my-push-token-123"
        val provider = CloudRegistrationProvider(initData)
        provider.initiate(
            accountName = "test@example.com",
            pushToken = testPushToken,
            httpClient = httpClient
        )

        assertEquals(testPushToken, provider.pushToken)
    }

    /**
     * Test initiate() with empty pushToken sets empty string.
     */
    @Test
    fun testInitiate_WithEmptyPushTokenSetsEmptyString() = runTest {
        val initData = """
            {
                "code": "code",
                "accountName": "test@example.com",
                "registrationUri": "https://example.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {},
                    "registrationUri": "https://example.com/v1.0/authenticators/registration",
                    "serviceName": "Test"
                },
                "id": "id",
                "accessToken": "token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "refresh"
            }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            respond(
                content = registrationResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        val provider = CloudRegistrationProvider(initData)
        provider.initiate(
            accountName = "test@example.com",
            pushToken = "",
            httpClient = httpClient
        )

        assertEquals("", provider.pushToken)
    }

    /**
     * Test initiate() response parsing creates correct metadata.
     */
    @Test
    fun testInitiate_ResponseParsingCreatesCorrectMetadata() = runTest {
        val initData = """
            {
                "code": "code",
                "accountName": "test@example.com",
                "registrationUri": "https://example.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 7200,
                "metadata": {
                    "authenticationMethods": {
                        "signature_fingerprint": {
                            "enrollmentUri": "https://example.com/v1.0/authnmethods/signatures",
                            "attributes": {"algorithm": "RSASHA512"},
                            "enabled": true
                        }
                    },
                    "registrationUri": "https://example.com/v1.0/authenticators/registration",
                    "serviceName": "My Test Service",
                    "featureFlags": ["feature1", "feature2"],
                    "customAttributes": {"custom1": "value1"},
                    "themeAttributes": {"primaryColor": "#FF0000"}
                },
                "id": "auth-id-456",
                "accessToken": "access-token-789",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "refresh-token-012"
            }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            respond(
                content = registrationResponseJson,
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        val provider = CloudRegistrationProvider(initData)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "token",
            httpClient = httpClient
        )

        assertTrue(result.isSuccess)
        val data = result.getOrNull()
        assertNotNull(data)
        assertEquals("auth-id-456", data?.metadata?.id)
        assertEquals("My Test Service", data?.metadata?.serviceName)
        assertTrue(data?.metadata?.features?.contains("feature1") == true)
        assertTrue(data?.metadata?.custom?.containsKey("custom1") == true)
        assertTrue(data?.metadata?.theme?.containsKey("primaryColor") == true)
    }

    /**
     * Test enroll() successfully enrolls a fingerprint signature and returns 201 Created.
     */
    @Test
    fun testEnroll_FingerprintSignature_Success() = runTest {
        val initData = """
            {
                "code": "test-code",
                "accountName": "test@example.com",
                "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {
                        "signature_fingerprint": {
                            "enrollmentUri": "https://sdk.verify.ibm.com/v1.0/authnmethods/signatures",
                            "attributes": {"algorithm": "RSASHA256"},
                            "enabled": true
                        }
                    },
                    "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                    "serviceName": "Test Service"
                },
                "id": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                "accessToken": "test-access-token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "test-refresh-token"
            }
        """.trimIndent()

        val enrollmentResponseJson = """
            [{
                "owner": "664002H4LX",
                "enrollmentUri": "https://sdk.verify.ibm.com/v1.0/authnmethods/signatures/a3e4bc8c-926d-4308-a80f-24c827f0446b",
                "methodType": "signature",
                "creationTime": "2026-02-11T05:43:01.826Z",
                "validated": true,
                "subType": "fingerprint",
                "attributes": {
                    "deviceSecurity": true,
                    "authenticatorUri": "https://sdk.verify.ibm.com/v1.0/authenticators/5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                    "authenticatorId": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                    "additionalData": [{
                        "name": "name",
                        "value": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd.FINGERPRINT"
                    }],
                    "algorithm": "RSASHA256"
                },
                "id": "a3e4bc8c-926d-4308-a80f-24c827f0446b",
                "enabled": true
            }]
        """.trimIndent()

        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            when (requestCount) {
                1 -> {
                    // First request: initiate registration
                    assertEquals(
                        "https://sdk.verify.ibm.com/v1.0/authenticators/registration?skipTotpEnrollment=true",
                        request.url.toString()
                    )
                    respond(
                        content = registrationResponseJson,
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }

                2 -> {
                    // Second request: enroll signature
                    assertEquals(
                        "https://sdk.verify.ibm.com/v1.0/authnmethods/signatures",
                        request.url.toString()
                    )
                    assertEquals(io.ktor.http.HttpMethod.Post, request.method)

                    // Verify Authorization header
                    assertTrue(request.headers[HttpHeaders.Authorization]?.startsWith("Bearer ") == true)
                    assertEquals(
                        ContentType.Application.Json.toString(),
                        request.body.contentType?.toString()
                    )

                    respond(
                        content = enrollmentResponseJson,
                        status = HttpStatusCode.Created
                    )
                }

                else -> {
                    respond(
                        content = "{}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }
            }
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        val provider = CloudRegistrationProvider(initData)
        provider.initiate(
            accountName = "test@example.com",
            pushToken = "test-push-token",
            httpClient = httpClient
        )

        // Perform enrollment with explicit keyName, publicKey, and signedData
        provider.enrollBiometric(
            httpClient = httpClient
        )

        // Verify both requests were made
        assertEquals(2, requestCount)
    }

    @Test
    fun testEnroll_FaceSignature_Success() = runTest {
        val initData = """
            {
                "code": "test-code",
                "accountName": "test@example.com",
                "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {
                        "signature_face": {
                            "enrollmentUri": "https://sdk.verify.ibm.com/v1.0/authnmethods/signatures",
                            "attributes": {"algorithm": "RSASHA256"},
                            "enabled": true
                        }
                    },
                    "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                    "serviceName": "Test Service"
                },
                "id": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                "accessToken": "test-access-token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "test-refresh-token"
            }
        """.trimIndent()

        val enrollmentResponseJson = """
            [{
                "owner": "664002H4LX",
                "enrollmentUri": "https://sdk.verify.ibm.com/v1.0/authnmethods/signatures/a3e4bc8c-926d-4308-a80f-24c827f0446b",
                "methodType": "signature",
                "creationTime": "2026-02-11T05:43:01.826Z",
                "validated": true,
                "subType": "face",
                "attributes": {
                    "deviceSecurity": true,
                    "authenticatorUri": "https://sdk.verify.ibm.com/v1.0/authenticators/5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                    "authenticatorId": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                    "additionalData": [{
                        "name": "name",
                        "value": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd.FACE"
                    }],
                    "algorithm": "RSASHA256"
                },
                "id": "a3e4bc8c-926d-4308-a80f-24c827f0446b",
                "enabled": true
            }]
        """.trimIndent()

        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            when (requestCount) {
                1 -> {
                    // First request: initiate registration
                    assertEquals(
                        "https://sdk.verify.ibm.com/v1.0/authenticators/registration?skipTotpEnrollment=true",
                        request.url.toString()
                    )
                    respond(
                        content = registrationResponseJson,
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }

                2 -> {
                    // Second request: enroll signature
                    assertEquals(
                        "https://sdk.verify.ibm.com/v1.0/authnmethods/signatures",
                        request.url.toString()
                    )
                    assertEquals(io.ktor.http.HttpMethod.Post, request.method)

                    // Verify Authorization header
                    assertTrue(request.headers[HttpHeaders.Authorization]?.startsWith("Bearer ") == true)
                    assertEquals(
                        ContentType.Application.Json.toString(),
                        request.body.contentType?.toString()
                    )

                    respond(
                        content = enrollmentResponseJson,
                        status = HttpStatusCode.Created
                    )
                }

                else -> {
                    respond(
                        content = "{}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }
            }
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        val provider = CloudRegistrationProvider(initData)
        provider.initiate(
            accountName = "test@example.com",
            pushToken = "test-push-token",
            httpClient = httpClient
        )

        // Perform enrollment with explicit keyName, publicKey, and signedData
        provider.enrollBiometric(
            httpClient = httpClient
        )

        // Verify both requests were made
        assertEquals(2, requestCount)
    }

    @Test
    fun testEnroll_UserPresenceSignature_Success() = runTest {
        val initData = """
            {
                "code": "test-code",
                "accountName": "test@example.com",
                "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val registrationResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {
                        "signature_userPresence": {
                            "enrollmentUri": "https://sdk.verify.ibm.com/v1.0/authnmethods/signatures",
                            "attributes": {"algorithm": "RSASHA256"},
                            "enabled": true
                        }
                    },
                    "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                    "serviceName": "Test Service"
                },
                "id": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                "accessToken": "test-access-token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "test-refresh-token"
            }
        """.trimIndent()

        val enrollmentResponseJson = """
            [{
                "owner": "664002H4LX",
                "enrollmentUri": "https://sdk.verify.ibm.com/v1.0/authnmethods/signatures/a3e4bc8c-926d-4308-a80f-24c827f0446b",
                "methodType": "signature",
                "creationTime": "2026-02-11T05:43:01.826Z",
                "validated": true,
                "subType": "user_presence",
                "attributes": {
                    "deviceSecurity": true,
                    "authenticatorUri": "https://sdk.verify.ibm.com/v1.0/authenticators/5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                    "authenticatorId": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                    "additionalData": [{
                        "name": "name",
                        "value": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd.USER_PRESENCE"
                    }],
                    "algorithm": "RSASHA256"
                },
                "id": "a3e4bc8c-926d-4308-a80f-24c827f0446b",
                "enabled": true
            }]
        """.trimIndent()

        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            when (requestCount) {
                1 -> {
                    // First request: initiate registration
                    assertEquals(
                        "https://sdk.verify.ibm.com/v1.0/authenticators/registration?skipTotpEnrollment=true",
                        request.url.toString()
                    )
                    respond(
                        content = registrationResponseJson,
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }

                2 -> {
                    // Second request: enroll signature
                    assertEquals(
                        "https://sdk.verify.ibm.com/v1.0/authnmethods/signatures",
                        request.url.toString()
                    )
                    assertEquals(io.ktor.http.HttpMethod.Post, request.method)

                    // Verify Authorization header
                    assertTrue(request.headers[HttpHeaders.Authorization]?.startsWith("Bearer ") == true)
                    assertEquals(
                        ContentType.Application.Json.toString(),
                        request.body.contentType?.toString()
                    )

                    respond(
                        content = enrollmentResponseJson,
                        status = HttpStatusCode.Created
                    )
                }

                else -> {
                    respond(
                        content = "{}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }
            }
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        val provider = CloudRegistrationProvider(initData)
        provider.initiate(
            accountName = "test@example.com",
            pushToken = "test-push-token",
            httpClient = httpClient
        )

        // Perform enrollment with explicit keyName, publicKey, and signedData
        provider.enrollUserPresence(
            httpClient = httpClient
        )

        // Verify both requests were made
        assertEquals(2, requestCount)
    }

    @Test
    fun testFinalize_Success() = runTest {
        val initData = """
            {
                "code": "test-code",
                "accountName": "test@example.com",
                "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val initiateResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {},
                    "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                    "serviceName": "Test Service",
                    "id": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd"
                },
                "id": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                "accessToken": "test-access-token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "test-refresh-token-initial"
            }
        """.trimIndent()

        val finalizeResponseJson = """
            {
                "expiresIn": 3600,
                "id": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                "accessToken": "test-access-token-final",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "test-refresh-token-final"
            }
        """.trimIndent()

        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            when (requestCount) {
                1 -> {
                    // First request: initiate registration
                    assertEquals(
                        "https://sdk.verify.ibm.com/v1.0/authenticators/registration?skipTotpEnrollment=true",
                        request.url.toString()
                    )
                    respond(
                        content = initiateResponseJson,
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }

                2 -> {
                    // Second request: finalize registration
                    assertEquals(
                        "https://sdk.verify.ibm.com/v1.0/authenticators/registration?metadataInResponse=false",
                        request.url.toString()
                    )
                    assertEquals(io.ktor.http.HttpMethod.Post, request.method)
                    assertEquals(
                        ContentType.Application.Json.toString(),
                        request.body.contentType?.toString()
                    )

                    // Verify request body contains refreshToken and attributes with pushToken
                    val bodyText = (request.body as TextContent).text
                    assertTrue(bodyText.contains("refreshToken"))
                    assertTrue(bodyText.contains("test-refresh-token-initial"))
                    assertTrue(bodyText.contains("pushToken"))
                    assertTrue(bodyText.contains("test-push-token"))

                    respond(
                        content = finalizeResponseJson,
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }

                else -> {
                    respond(
                        content = "{}",
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }
            }
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        val provider = CloudRegistrationProvider(initData)

        // Initiate registration first
        provider.initiate(
            accountName = "test@example.com",
            pushToken = "test-push-token",
            httpClient = httpClient
        )

        // Finalize registration
        val result = provider.finalize(httpClient = httpClient)

        // Verify both requests were made
        assertEquals(2, requestCount)

        // Verify result is successful
        assertTrue(result.isSuccess)

        // Verify the authenticator descriptor
        val authenticator = result.getOrNull()
        assertNotNull(authenticator)
        assertEquals("5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd", authenticator?.id)
        assertEquals("Test Service", authenticator?.serviceName)
        assertEquals("test@example.com", authenticator?.accountName)
    }

    @Test
    fun testFinalize_WithoutInitiate_Failure() = runTest {
        val initData = """
            {
                "code": "test-code",
                "accountName": "test@example.com",
                "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            respond(
                content = "{}",
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType,
                    ContentType.Application.Json.toString()
                )
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

        val provider = CloudRegistrationProvider(initData)

        // Try to finalize without calling initiate first
        val result = provider.finalize(httpClient = httpClient)

        // Verify result is a failure
        assertTrue(result.isFailure)
    }

    @Test
    fun testFinalize_ServerError_Failure() = runTest {
        val initData = """
            {
                "code": "test-code",
                "accountName": "test@example.com",
                "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                "version": {"number": "1.0.0", "platform": "test"}
            }
        """.trimIndent()

        val initiateResponseJson = """
            {
                "expiresIn": 3600,
                "metadata": {
                    "authenticationMethods": {},
                    "registrationUri": "https://sdk.verify.ibm.com/v1.0/authenticators/registration",
                    "serviceName": "Test Service",
                    "id": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd"
                },
                "id": "5bbdcd60-92a0-4e0f-a14c-72cb1b8358cd",
                "accessToken": "test-access-token",
                "version": {"number": "1.0.0", "platform": "test"},
                "refreshToken": "test-refresh-token"
            }
        """.trimIndent()

        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            when (requestCount) {
                1 -> {
                    // First request: initiate registration succeeds
                    respond(
                        content = initiateResponseJson,
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }

                2 -> {
                    // Second request: finalize registration fails
                    respond(
                        content = """{"error":"server_error","errorDescription":"Internal server error"}""",
                        status = HttpStatusCode.InternalServerError,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            ContentType.Application.Json.toString()
                        )
                    )
                }

                else -> {
                    respond(
                        content = "{}",
                        status = HttpStatusCode.OK
                    )
                }
            }
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    encodeDefaults = true
                })
            }
        }

        val provider = CloudRegistrationProvider(initData)

        // Initiate registration first
        provider.initiate(
            accountName = "test@example.com",
            pushToken = "test-push-token",
            httpClient = httpClient
        )

        // Try to finalize - should fail due to server error
        val result = provider.finalize(httpClient = httpClient)

        // Verify both requests were made
        assertEquals(2, requestCount)

        // Verify result is a failure
        assertTrue(result.isFailure)

        // Verify exception type
        val exception = result.exceptionOrNull()
        assertNotNull(exception)
        assertTrue(exception is MFARegistrationException.General)
    }
}
