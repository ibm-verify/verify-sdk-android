/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ibm.security.verifysdk.core.helper.ContextHelper
import com.ibm.security.verifysdk.core.helper.NetworkHelper
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
import kotlin.test.assertNotEquals

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
            "options": "ignoreSslCerts=false"
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
            "options": "ignoreSslCerts=false"
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
                          "authenticator_id": "uuidtest-authenticator-id-001",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser@example.com",
                          "expires_in": 3599
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            "application/json;charset=UTF-8"
                        )
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
            assertEquals(
                "uuidtest-authenticator-id-001",
                data.tokenInfo.additionalData["authenticator_id"]
            )
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
            "options": "ignoreSslCerts=false"
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
            "options": "ignoreSslCerts=false"
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
            "options": "ignoreSslCerts=false"
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
                          "authenticator_id": "uuidtest-authenticator-id-001",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser@example.com",
                          "expires_in": 3599
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            "application/json;charset=UTF-8"
                        )
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
            assertNotEquals(
                "uuidtest-authenticator-id-001",
                authenticator.id,
                "Authenticator id should be client-side tenant_id, not server authenticator_id"
            )
            assertTrue(
                "Authenticator id should be a client-generated tenant_id without uuid prefix",
                !authenticator.id.startsWith("uuid")
            )
            assertEquals(
                "Server authenticator_id should remain in token additionalData",
                "uuidtest-authenticator-id-001",
                authenticator.token.additionalData["authenticator_id"]
            )
            assertEquals("Test Service", authenticator.serviceName)
            assertEquals("testuser@example.com", authenticator.accountName)
            assertEquals("test_access_token_final", authenticator.token.accessToken)
            assertEquals("test_refresh_token_final", authenticator.token.refreshToken)
        }

        httpClient.close()
    }

    @Test
    fun testFinalize_FailsWhenClientAuthenticatorIdMatchesServerAuthenticatorId() = runTest {
        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "options": "ignoreSslCerts=false"
        }
        """.trimIndent()

        val serverAuthenticatorId = "uuidserver-authenticator-id-001"

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
                          "authenticator_id": "$serverAuthenticatorId",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser@example.com",
                          "expires_in": 3599
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            "application/json;charset=UTF-8"
                        )
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
        val initResult = provider.initiate(
            accountName = "testuser@example.com",
            pushToken = "test_push_token",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", initResult.isSuccess)

        val result = provider.finalize(httpClient)

        assertTrue("Finalize should succeed", result.isSuccess)
        result.onSuccess { authenticator ->
            assertFalse(
                "Regression guard: authenticator.id must not equal server-side authenticator_id",
                authenticator.id == authenticator.token.additionalData["authenticator_id"]
            )
            assertNotEquals(
                "Regression guard: client authenticator.id must remain distinct from server authenticator_id",
                serverAuthenticatorId,
                authenticator.id
            )
        }

        httpClient.close()
    }

    @Test
    fun testFinalize_PreservesTenantIdAndServerAuthenticatorIdAcrossRegistrationAndRefresh() =
        runTest {
            val qrCodeJson = """
            {
                "code": "test_code",
                "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
                "client_id": "AuthenticatorClient",
                "options": "ignoreSslCerts=false"
            }
            """.trimIndent()

            val serverAuthenticatorId = "uuidserver-authenticator-id-001"
            val tokenResponses = mutableListOf<String>()

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
                        val responseBody = if (tokenResponses.isEmpty()) {
                            """
                        {
                          "access_token": "initial_access_token",
                          "refresh_token": "initial_refresh_token",
                          "scope": "mmfaAuthn",
                          "authenticator_id": "$serverAuthenticatorId",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser@example.com",
                          "expires_in": 3599
                        }
                        """.trimIndent()
                        } else {
                            """
                        {
                          "access_token": "refreshed_access_token",
                          "refresh_token": "refreshed_refresh_token",
                          "scope": "mmfaAuthn",
                          "authenticator_id": "$serverAuthenticatorId",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser@example.com",
                          "expires_in": 3599
                        }
                        """.trimIndent()
                        }
                        tokenResponses.add(responseBody)
                        respond(
                            content = responseBody,
                            status = HttpStatusCode.OK,
                            headers = headersOf(
                                HttpHeaders.ContentType,
                                "application/json;charset=UTF-8"
                            )
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

            val initResult = provider.initiate(
                accountName = "testuser@example.com",
                pushToken = "test_push_token",
                additionalHeaders = null,
                httpClient = httpClient
            )

            assertTrue("Initiate should succeed", initResult.isSuccess)

            val finalizeResult = provider.finalize(httpClient)
            assertTrue("Finalize should succeed", finalizeResult.isSuccess)

            finalizeResult.onSuccess { authenticator ->
                assertNotEquals(
                    serverAuthenticatorId,
                    authenticator.id,
                    "Server authenticator_id must not be stored as authenticator.id"
                )
                assertTrue(
                    "authenticator.id should remain the client tenant_id without uuid prefix",
                    !authenticator.id.startsWith("uuid")
                )
                assertEquals(
                    serverAuthenticatorId,
                    authenticator.token.additionalData["authenticator_id"]
                )
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
            "options": "ignoreSslCerts=false"
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
            "options": "ignoreSslCerts=false"
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
            "options": "ignoreSslCerts=false"
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
            "options": "ignoreSslCerts=false"
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
            "options": "ignoreSslCerts=false"
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

    /**
     * Test enrollment without service name in metadata.
     *
     * When service_name is not provided in metadata, the serviceName should default
     * to the host from the details_url.
     */
    @Test
    fun testEnrollNoServiceName_Success() = runTest {
        val qrCodeJson = """
        {
            "code": "test_authorization_code_002",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "options": "ignoreSslCerts=false"
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                // Details endpoint without service_name in metadata
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me",
                          "metadata": {},
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
                // Token endpoint
                request.url.encodedPath.contains("/oauth20/token") -> {
                    respond(
                        content = """
                        {
                          "access_token": "A1b2C3D4",
                          "refresh_token": "test_refresh_token_002",
                          "scope": "mmfaAuthn",
                          "authenticator_id": "test-authenticator-id-002",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser@example.com",
                          "expires_in": 3599
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            "application/json;charset=UTF-8"
                        )
                    )
                }
                // Enrollment endpoint
                request.url.encodedPath.contains("/scim/Me") -> {
                    respond(
                        content = """
                        {
                          "id": "test-authenticator-id-002",
                          "schemas": ["urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator"],
                          "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator": {
                            "enabled": true
                          }
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

        // Initiate with account name
        val initResult = provider.initiate(
            accountName = "OnPremise account",
            pushToken = "abc123",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", initResult.isSuccess)
        assertNotNull("Provider should not be null", provider)

        // Finalize enrollment
        val finalizeResult = provider.finalize(httpClient)

        assertTrue("Finalize should succeed", finalizeResult.isSuccess)
        finalizeResult.onSuccess { authenticator ->
            assertNotNull("Authenticator should not be null", authenticator)
            assertEquals("A1b2C3D4", authenticator.token.accessToken)
            // Service name should default to host when not provided in metadata
            assertEquals("test.example.com", authenticator.serviceName)
            // No factors enrolled yet
            assertFalse("User presence should not be enrolled", authenticator.userPresence != null)
            assertFalse("Biometric should not be enrolled", authenticator.biometric != null)
        }

        httpClient.close()
    }

    /**
     * Test enrollment without account name provided.
     *
     * When accountName is empty string, it remains empty in the authenticator.
     * The display_name from token response is stored in additionalData but not
     * automatically assigned to accountName.
     */
    @Test
    fun testEnrollNoAccountName_Success() = runTest {
        val qrCodeJson = """
        {
            "code": "test_authorization_code_003",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "options": "ignoreSslCerts=false"
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                // Details endpoint
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
                          "access_token": "A1b2C3D4",
                          "refresh_token": "test_refresh_token_003",
                          "scope": "mmfaAuthn",
                          "authenticator_id": "test-authenticator-id-003",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser",
                          "expires_in": 3599
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            "application/json;charset=UTF-8"
                        )
                    )
                }
                // Enrollment endpoint
                request.url.encodedPath.contains("/scim/Me") -> {
                    respond(
                        content = """
                        {
                          "id": "test-authenticator-id-003",
                          "schemas": ["urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator"],
                          "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator": {
                            "enabled": true
                          }
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

        // Initiate with empty account name
        val initResult = provider.initiate(
            accountName = "",
            pushToken = "abc123",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", initResult.isSuccess)
        assertNotNull("Provider should not be null", provider)

        // Finalize enrollment
        val finalizeResult = provider.finalize(httpClient)

        assertTrue("Finalize should succeed", finalizeResult.isSuccess)
        finalizeResult.onSuccess { authenticator ->
            assertNotNull("Authenticator should not be null", authenticator)
            assertEquals("A1b2C3D4", authenticator.token.accessToken)
            // Account name remains empty as passed to initiate()
            assertEquals("", authenticator.accountName)
            // display_name is available in token additionalData
            assertEquals("testuser", authenticator.token.additionalData["display_name"])
            // No biometric enrolled yet
            assertFalse("Biometric should not be enrolled", authenticator.biometric != null)
        }

        httpClient.close()
    }

    /**
     * Test enrollment without metadata field in the payload.
     *
     * When the metadata field is completely omitted from the server response,
     * the service name should default to the hostname.
     */
    @Test
    fun testEnrollNoMetadataField_Success() = runTest {
        val qrCodeJson = """
        {
            "code": "test_authorization_code_003",
            "details_url": "https://test.example.com/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "options": "ignoreSslCerts=false"
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when {
                // Details endpoint without metadata field at all
                request.url.encodedPath.contains("/details") -> {
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://test.example.com/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending",
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
                          "access_token": "X9y8Z7W6",
                          "refresh_token": "test_refresh_token_003",
                          "scope": "mmfaAuthn",
                          "authenticator_id": "test-authenticator-id-003",
                          "ISV_push_enabled": "true",
                          "token_type": "bearer",
                          "display_name": "testuser@example.com",
                          "expires_in": 3599
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType,
                            "application/json;charset=UTF-8"
                        )
                    )
                }
                // Enrollment endpoint
                request.url.encodedPath.contains("/scim/Me") -> {
                    respond(
                        content = """
                        {
                          "id": "test-authenticator-id-003",
                          "schemas": ["urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator"],
                          "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator": {
                            "enabled": true
                          }
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

        // Initiate with account name
        val initResult = provider.initiate(
            accountName = "OnPremise account",
            pushToken = "abc123",
            additionalHeaders = null,
            httpClient = httpClient
        )

        assertTrue("Initiate should succeed", initResult.isSuccess)
        assertNotNull("Provider should not be null", provider)

        // Finalize enrollment
        val finalizeResult = provider.finalize(httpClient)

        assertTrue("Finalize should succeed", finalizeResult.isSuccess)
        finalizeResult.onSuccess { authenticator ->
            assertNotNull("Authenticator should not be null", authenticator)
            assertEquals("X9y8Z7W6", authenticator.token.accessToken)
            // Service name should default to host when metadata field is completely omitted
            assertEquals("test.example.com", authenticator.serviceName)
            // No factors enrolled yet
            assertFalse("User presence should not be enrolled", authenticator.userPresence != null)
            assertFalse("Biometric should not be enrolled", authenticator.biometric != null)
        }

        httpClient.close()
    }

    /**
     * Test: Verify ignoreSslCerts=true works when allowInsecureSSL=true.
     *
     * This test verifies the two-level security model allows SSL bypass when both conditions are met:
     * 1. QR code requests it (ignoreSslCerts=true)
     * 2. App permits it (NetworkHelper.allowInsecureSSL=true)
     */
    @Test
    fun testIgnoreSslCerts_AllowedWhenPermitted() = runTest {
        NetworkHelper.allowInsecureSSL = true

        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://localhost:9443/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "options":"ignoreSslCerts=true"
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when (request.url.toString()) {
                "https://localhost:9443/mga/sps/mmfa/user/mgmt/details" -> {
                    // First request: details endpoint
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://localhost:9443/scim/Me",
                          "metadata": {
                            "service_name": "Test Service"
                          },
                          "discovery_mechanisms": [
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence"
                          ],
                          "enrollment_endpoint": "https://localhost:9443/scim/Me",
                          "qrlogin_endpoint": "https://localhost:9443/mga/sps/apiauthsvc/policy/qrcode_response",
                          "hotp_shared_secret_endpoint": "https://localhost:9443/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://localhost:9443/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://localhost:9443/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                "https://localhost:9443/token" -> {
                    // Second request: OAuth token endpoint
                    respond(
                        content = """{"access_token":"test_token","token_type":"Bearer","expires_in":3600,"authenticator_id":"test_auth_id"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> error("Unexpected request: ${request.url}")
            }
        }

        NetworkHelper.initialize(httpClientEngine = mockEngine)

        try {
            val provider = OnPremiseRegistrationProvider(qrCodeJson)
            val result = provider.initiate("test@example.com", "push_token", null)
            
            result.onFailure { it.printStackTrace() }
            assertTrue("Should succeed when SSL bypass is allowed", result.isSuccess)
        } finally {
            NetworkHelper.initialize()
            NetworkHelper.allowInsecureSSL = false
        }
    }

    /**
     * Test: Verify ignoreSslCerts=false uses secure client.
     *
     * When ignoreSslCerts=false, the default secure client should be used.
     */
    @Test
    fun testIgnoreSslCerts_UsesSecureClientWhenFalse() = runTest {
        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://localhost:9443/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "options":"ignoreSslCerts=false"
        }
        """.trimIndent()

        val mockEngine = MockEngine { request ->
            when (request.url.toString()) {
                "https://localhost:9443/mga/sps/mmfa/user/mgmt/details" -> {
                    // First request: details endpoint
                    respond(
                        content = """
                        {
                          "authntrxn_endpoint": "https://localhost:9443/scim/Me",
                          "metadata": {
                            "service_name": "Test Service"
                          },
                          "discovery_mechanisms": [
                            "urn:ibm:security:authentication:asf:mechanism:mobile_user_approval:user_presence"
                          ],
                          "enrollment_endpoint": "https://localhost:9443/scim/Me",
                          "qrlogin_endpoint": "https://localhost:9443/mga/sps/apiauthsvc/policy/qrcode_response",
                          "hotp_shared_secret_endpoint": "https://localhost:9443/mga/sps/mga/user/mgmt/otp/hotp",
                          "totp_shared_secret_endpoint": "https://localhost:9443/mga/sps/mga/user/mgmt/otp/totp",
                          "version": "11.0.1.0",
                          "token_endpoint": "https://localhost:9443/token"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                "https://localhost:9443/token" -> {
                    // Second request: OAuth token endpoint
                    respond(
                        content = """{"access_token":"test_token","token_type":"Bearer","expires_in":3600,"authenticator_id":"test_auth_id"}""",
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/json")
                    )
                }
                else -> error("Unexpected request: ${request.url}")
            }
        }

        NetworkHelper.initialize(httpClientEngine = mockEngine)

        try {
            val provider = OnPremiseRegistrationProvider(qrCodeJson)
            val result = provider.initiate("test@example.com", "push_token", null)
            
            result.onFailure { it.printStackTrace() }
            assertTrue("Should succeed with secure client", result.isSuccess)
        } finally {
            NetworkHelper.initialize()
        }
    }

    /**
     * Security test: Verify SSL bypass is blocked when allowInsecureSSL = false.
     *
     * This test ensures the two-level security model prevents SSL bypass when:
     * 1. QR code requests it (ignoreSslCerts=true)
     * 2. App denies it (NetworkHelper.allowInsecureSSL=false)
     *
     * Expected: initiate() returns Result.failure with IllegalStateException
     */
    @Test
    fun testIgnoreSslCerts_BlockedWhenNotAllowed() = runTest {
        NetworkHelper.allowInsecureSSL = false

        val qrCodeJson = """
        {
            "code": "test_code",
            "details_url": "https://localhost:9443/mga/sps/mmfa/user/mgmt/details",
            "client_id": "AuthenticatorClient",
            "options":"ignoreSslCerts=true"
        }
        """.trimIndent()

        val provider = OnPremiseRegistrationProvider(qrCodeJson)
        val result = provider.initiate("test@example.com", "push_token", null)

        assertTrue("Should fail when SSL bypass is requested but not allowed", result.isFailure)
        
        result.onFailure { exception ->
            assertTrue(
                "Should throw IllegalStateException about insecure SSL not being allowed",
                exception is IllegalStateException &&
                (exception.message?.contains("insecure", ignoreCase = true) == true ||
                 exception.message?.contains("SSL", ignoreCase = true) == true ||
                 exception.message?.contains("allowInsecureSSL", ignoreCase = true) == true)
            )
        }
    }
}
