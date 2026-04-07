/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.mfa.EnrollableType
import com.ibm.security.verifysdk.mfa.MFARegistrationException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.test.assertFailsWith

/**
 * Instrumented tests for OnPremiseRegistrationProvider based on network traces.
 * 
 * Tests cover:
 * 1. QR code parsing and initialization
 * 2. Details endpoint fetching (discovery mechanisms)
 * 3. Token exchange (OAuth authorization code flow)
 * 4. Factor enrollment (UserPresence, Biometric)
 * 5. Finalization with token refresh
 * 
 * Based on CloudRegistrationProviderTest pattern with OnPremise-specific adaptations.
 * Network trace source: v3-ivia.txt lines 33-243
 */
@RunWith(AndroidJUnit4::class)
class OnPremiseRegistrationProviderTest {

    @Before
    fun setUp() {
        ContextHelper.init(InstrumentationRegistry.getInstrumentation().targetContext)
    }

    /**
     * Test QR code parsing and initialization.
     * 
     * Based on log lines 33-67:
     * - QR code contains: code, uri, clientId, ignoreSSLCertificate
     * - GET to /mga/sps/mmfa/user/mgmt/details returns discovery mechanisms
     */
    @Test
    fun testQrCodeParsing_Success() = runTest {
        val qrCodeJson = """
        {
            "code": "test_authorization_code_001",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val provider = OnPremiseRegistrationProvider(qrCodeJson)

        // Verify provider was created successfully
        assertNotNull(provider)
    }

    /**
     * Test QR code parsing with invalid JSON.
     */
    @Test
    fun testQrCodeParsing_InvalidJson_ThrowsException() {
        val invalidJson = "{ invalid json }"

        assertFailsWith<MFARegistrationException.FailedToParse> {
            OnPremiseRegistrationProvider(invalidJson)
        }
    }

    /**
     * Test initiate() fetches details and exchanges token.
     * 
     * Based on log lines 33-127:
     * - GET to details endpoint returns discovery mechanisms and endpoints
     * - POST to token endpoint with authorization code
     * - Returns access_token, refresh_token, authenticator_id
     */
    @Test
    fun testInitiate_Success() = runTest {
        val qrCodeJson = """
        {
            "code": "test_authorization_code_001",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                // Details endpoint
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending",
                          "metadata": {
                            "service_name": "Test Service"
                          },
                          "discovery_mechanisms": [
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence",
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:fingerprint"
                          ],
                          "enrollment_endpoint": "https://test.example.com/scim/Me",
                          "qrlogin_endpoint": "https://test.example.com/mga/sps/apiauthsvc/policy/qrcode_response",
                          "hotp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                // Token endpoint
                request.url.encodedPath.contains("/oauth20/token") -> {
                    respond(
                        content = """
                        {
                          "access_token": "test_access_token_001",
                          "refresh_token": "test_refresh_token_001",
                          "scope": "mmfaAuthn",
                          "authenticator_id": "test-authenticator-id-001",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser@example.com",
                          "expires_in": 3599
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json;charset=UTF-8")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
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

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        val result = provider.initiate(
            accountName = "testuser@example.com",
            pushToken = "test_push_token_fcm",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", result.isSuccess)
        result.onSuccess { data ->
            assertNotNull("Token info should not be null", data.tokenInfo)
            assertEquals("test_access_token_001", data.tokenInfo.accessToken)
            assertEquals("test_refresh_token_001", data.tokenInfo.refreshToken)
            assertEquals("Test Service", data.metadata.serviceName)
        }

        httpClient.close()
    }

    /**
     * Test that canEnrollUserPresence returns true when available.
     *
     * Based on log lines 43-67:
     * - discovery_mechanisms includes user_presence
     */
    @Test
    fun testCanEnrollUserPresence_WhenAvailable() = runTest {
        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me",
                          "metadata": {"service_name": "Test"},
                          "discovery_mechanisms": [
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence"
                          ],
                          "enrollment_endpoint": "https://test.example.com/scim/Me",
                          "qrlogin_endpoint": "https://test.example.com/mga/sps/apiauthsvc/policy/qrcode_response",
                          "hotp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                request.url.encodedPath.contains("/oauth20/token") -> {
                    respond(
                        content = """
                        {
                          "access_token": "test_token",
                          "refresh_token": "test_refresh",
                          "authenticator_id": "test-id",
                          "expires_in": 3600
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
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

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "test_push",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", result.isSuccess)
        assertTrue("Should be able to enroll user presence", provider.canEnrollUserPresence)

        httpClient.close()
    }

    /**
     * Test that canEnrollBiometric returns true when fingerprint is available.
     *
     * Based on log lines 43-67:
     * - discovery_mechanisms includes fingerprint
     */
    @Test
    fun testCanEnrollBiometric_WhenFingerprintAvailable() = runTest {
        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me",
                          "metadata": {"service_name": "Test"},
                          "discovery_mechanisms": [
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:fingerprint"
                          ],
                          "enrollment_endpoint": "https://test.example.com/scim/Me",
                          "qrlogin_endpoint": "https://test.example.com/mga/sps/apiauthsvc/policy/qrcode_response",
                          "hotp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                request.url.encodedPath.contains("/oauth20/token") -> {
                    respond(
                        content = """
                        {
                          "access_token": "test_token",
                          "refresh_token": "test_refresh",
                          "authenticator_id": "test-id",
                          "expires_in": 3600
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
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

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "test_push",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", result.isSuccess)
        assertTrue("Should be able to enroll biometric", provider.canEnrollBiometric)

        httpClient.close()
    }

    /**
     * Test finalize() performs token refresh.
     * 
     * Based on log lines 208-243:
     * - POST to token endpoint with grant_type=refresh_token
     * - Returns new access_token and refresh_token
     * - Creates OnPremiseAuthenticator with all enrolled factors
     */
    @Test
    fun testFinalize_Success() = runTest {
        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me",
                          "metadata": {"service_name": "Test Service"},
                          "discovery_mechanisms": [
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence"
                          ],
                          "enrollment_endpoint": "https://test.example.com/scim/Me",
                          "qrlogin_endpoint": "https://test.example.com/mga/sps/apiauthsvc/policy/qrcode_response",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token",
                          "hotp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                request.url.encodedPath.contains("/oauth20/token") -> {
                    respond(
                        content = """
                        {
                          "access_token": "test_access_token_final",
                          "refresh_token": "test_refresh_token_final",
                          "scope": "mmfaAuthn",
                          "authenticator_id": "test-authenticator-id-001",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser@example.com",
                          "expires_in": 3599
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json;charset=UTF-8")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
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

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        
        // Initialize first
        val initResult = provider.initiate(
            accountName = "testuser@example.com",
            pushToken = "test_push_token",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", initResult.isSuccess)

        // Finalize
        val result = provider.finalize(httpClient)

        assertTrue("Finalize should succeed", result.isSuccess)
        result.onSuccess { authenticator ->
            assertNotNull("Authenticator should not be null", authenticator)
            assertEquals("test-authenticator-id-001", authenticator.id)
            assertEquals("Test Service", authenticator.serviceName)
            assertEquals("testuser@example.com", authenticator.accountName)
            assertEquals("test_access_token_final", authenticator.token.accessToken)
            assertEquals("test_refresh_token_final", authenticator.token.refreshToken)
        }

        httpClient.close()
    }

    /**
     * Test initiate() failure when details endpoint returns error.
     */
    @Test
    fun testInitiate_DetailsEndpointError_ThrowsException() = runTest {
        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            respond(
                content = """{"error": "Invalid request"}""",
                status = HttpStatusCode.BadRequest,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
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

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "test_push",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should fail", result.isFailure)

        httpClient.close()
    }

    /**
     * Test initiate() failure when token endpoint returns error.
     */
    @Test
    fun testInitiate_TokenEndpointError_ThrowsException() = runTest {
        val qrCodeJson = """
        {
            "code": "invalid_code",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me",
                          "metadata": {"service_name": "Test"},
                          "discovery_mechanisms": [],
                          "enrollment_endpoint": "https://test.example.com/scim/Me",
                          "qrlogin_endpoint": "https://test.example.com/mga/sps/apiauthsvc/policy/qrcode_response",
                          "hotp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                request.url.encodedPath.contains("/oauth20/token") -> {
                    respond(
                        content = """{"error": "invalid_grant"}""",
                        status = HttpStatusCode.BadRequest,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
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

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "test_push",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should fail with invalid code", result.isFailure)

        httpClient.close()
    }

    /**
     * Test that serviceName is accessible after initialization.
     */
    @Test
    fun testServiceName_AfterInitialization() = runTest {
        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me",
                          "metadata": {"service_name": "Test Service"},
                          "discovery_mechanisms": [
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence"
                          ],
                          "enrollment_endpoint": "https://test.example.com/scim/Me",
                          "qrlogin_endpoint": "https://test.example.com/mga/sps/apiauthsvc/policy/qrcode_response",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token",
                          "hotp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                request.url.encodedPath.contains("/oauth20/token") -> {
                    respond(
                        content = """
                        {
                          "access_token": "test_token",
                          "refresh_token": "test_refresh",
                          "authenticator_id": "test-id",
                          "expires_in": 3600
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
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

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        
        // Before initialization, serviceName should be empty
        assertEquals("", provider.serviceName)

        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "test_push",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", result.isSuccess)
        // After initialization, serviceName should be set
        assertEquals("Test Service", provider.serviceName)

        httpClient.close()
    }

    /**
     * Test that countOfAvailableEnrollments reflects discovery mechanisms.
     */
    @Test
    fun testCountOfAvailableEnrollments() = runTest {
        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me",
                          "metadata": {"service_name": "Test"},
                          "discovery_mechanisms": [
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence",
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:fingerprint"
                          ],
                          "enrollment_endpoint": "https://test.example.com/scim/Me",
                          "qrlogin_endpoint": "https://test.example.com/mga/sps/apiauthsvc/policy/qrcode_response",
                          "hotp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                request.url.encodedPath.contains("/oauth20/token") -> {
                    respond(
                        content = """
                        {
                          "access_token": "test_token",
                          "refresh_token": "test_refresh",
                          "authenticator_id": "test-id",
                          "expires_in": 3600
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
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

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "test_push",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", result.isSuccess)
        // Should have 2 available enrollments (user_presence + fingerprint)
        assertEquals(2, provider.countOfAvailableEnrollments)

        httpClient.close()
    }

    /**
     * Test that initiate() succeeds even when no enrollable factors are available.
     * Note: The SDK allows registration with no factors - factors can be enrolled later.
     */
    @Test
    fun testInitiate_NoEnrollableFactors_Succeeds() = runTest {
        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "ignoreSSLCertificate": false
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me",
                          "metadata": {"service_name": "Test"},
                          "discovery_mechanisms": [],
                          "enrollment_endpoint": "https://test.example.com/scim/Me",
                          "qrlogin_endpoint": "https://test.example.com/mga/sps/apiauthsvc/policy/qrcode_response",
                          "hotp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://test.example.com/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://test.example.com/mga/sps/oauth/oauth20/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                request.url.encodedPath.contains("/oauth20/token") -> {
                    respond(
                        content = """
                        {
                          "access_token": "test_token",
                          "refresh_token": "test_refresh",
                          "authenticator_id": "test-id",
                          "expires_in": 3600
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
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

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        val result = provider.initiate(
            accountName = "test@example.com",
            pushToken = "test_push",
            additionalHeaders = null,
            httpClient = httpClient
        )

        // Should succeed even with no enrollable factors
        assertTrue("Should succeed even with no enrollable factors", result.isSuccess)
        assertEquals(0, provider.countOfAvailableEnrollments)

        httpClient.close()
    }
}
