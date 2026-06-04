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
import kotlin.test.DefaultAsserter.assertNotNull

/**
 * Test suite for OnPremiseAuthenticatorService to verify:
 * 1. HttpClient constructor injection
 * 2. Token persistence callback (blocking)
 * 3. Immutable service design
 * 4. OnPremise-specific properties (clientId, ignoreSslCertificate)
 * 
 * Based on CloudAuthenticatorServiceTest pattern with OnPremise-specific adaptations.
 */
@RunWith(AndroidJUnit4::class)
class OnPremiseAuthenticatorServiceTest {

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
                content = """
                {
                  "access_token": "new_token",
                  "refresh_token": "new_refresh",
                  "scope": "mmfaAuthn",
                  "authenticator_id": "test_authenticator_id",
                  "token_type": "bearer",
                  "expires_in": 3600
                }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json;charset=UTF-8")
            )
        }

        val httpClient = HttpClient(mockEngine)

        // HttpClient is now a constructor parameter
        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "AuthenticatorClient",
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
                content = """
                {
                  "access_token": "persisted_token",
                  "refresh_token": "persisted_refresh",
                  "scope": "mmfaAuthn",
                  "authenticator_id": "test_authenticator_id",
                  "token_type": "bearer",
                  "expires_in": 3600
                }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json;charset=UTF-8")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "AuthenticatorClient",
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
                content = """
                {
                  "access_token": "new_token",
                  "refresh_token": "new_refresh",
                  "scope": "mmfaAuthn",
                  "authenticator_id": "test_authenticator_id",
                  "token_type": "bearer",
                  "expires_in": 3600
                }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json;charset=UTF-8")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "AuthenticatorClient",
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
                content = """
                {
                  "access_token": "new_token",
                  "refresh_token": "new_refresh",
                  "scope": "mmfaAuthn",
                  "authenticator_id": "test_authenticator_id",
                  "token_type": "bearer",
                  "expires_in": 3600
                }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json;charset=UTF-8")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = OnPremiseAuthenticatorService(
            _accessToken = "original_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "AuthenticatorClient",
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

        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "TestClient",
            _authenticatorId = "test_id",
            httpClient = httpClient,
            _ignoreSslCertificate = true
        )

        assertEquals("test_token", service.accessToken)
        assertEquals("https://example.com/mga/sps/oauth/oauth20/token", service.refreshUri.toString())
        assertEquals("https://example.com/scim/Me", service.transactionUri.toString())
        assertEquals("test_id", service.authenticatorId)
        assertEquals("TestClient", service.clientId)
        assertTrue("ignoreSslCertificate should be true", service.ignoreSslCertificate)

        httpClient.close()
    }

    @Test
    fun testOnPremiseSpecificProperties() {
        // Verify OnPremise-specific properties (clientId, ignoreSslCertificate)
        val mockEngine = MockEngine { request ->
            respond(
                content = "{}",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine)

        // Test with SSL certificate validation enabled (default)
        val serviceWithSsl = OnPremiseAuthenticatorService(
            _accessToken = "test_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "AuthenticatorClient",
            _authenticatorId = "test_id",
            httpClient = httpClient
        )

        assertEquals("AuthenticatorClient", serviceWithSsl.clientId)
        assertEquals(false, serviceWithSsl.ignoreSslCertificate)

        // Test with SSL certificate validation disabled
        val serviceWithoutSsl = OnPremiseAuthenticatorService(
            _accessToken = "test_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "CustomClient",
            _authenticatorId = "test_id",
            httpClient = httpClient,
            _ignoreSslCertificate = true
        )

        assertEquals("CustomClient", serviceWithoutSsl.clientId)
        assertTrue("ignoreSslCertificate should be true", serviceWithoutSsl.ignoreSslCertificate)

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testTokenRefreshWithAdditionalData() {
        // Verify that additional data is passed correctly in token refresh
        var requestBody: String? = null

        val mockEngine = MockEngine { request ->
            // Capture request body for verification
            if (request.body is io.ktor.http.content.OutgoingContent.ByteArrayContent) {
                requestBody = (request.body as io.ktor.http.content.OutgoingContent.ByteArrayContent)
                    .bytes().decodeToString()
            }

            respond(
                content = """
                {
                  "access_token": "new_token",
                  "refresh_token": "new_refresh",
                  "scope": "mmfaAuthn",
                  "authenticator_id": "test_authenticator_id",
                  "token_type": "bearer",
                  "expires_in": 3600
                }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json;charset=UTF-8")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "AuthenticatorClient",
            _authenticatorId = "test_authenticator_id",
            httpClient = httpClient
        )

        runBlocking {
            val result = service.refreshToken(
                refreshToken = "test_refresh_token",
                accountName = "test@example.com",
                pushToken = "test_push_token",
                additionalData = mapOf(
                    "device_name" to "Test Device",
                    "platform_type" to "Android"
                )
            )

            assertTrue("refreshToken should succeed", result.isSuccess)
            
            // Verify additional data was included in request
            assertNotNull("Request body should not be null", requestBody)
            assertTrue("Request should include device_name", requestBody?.contains("device_name") == true)
            assertTrue("Request should include platform_type", requestBody?.contains("platform_type") == true)
        }

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testTokenRefresh_PersistsTenantIdSeparatelyFromServerAuthenticatorId() {
        var callbackAuthenticatorId: String? = null
        var persistedToken: TokenInfo? = null

        val callback = object : TokenPersistenceCallback {
            override suspend fun onTokenRefreshed(
                authenticatorId: String,
                newToken: TokenInfo
            ): Result<Unit> {
                callbackAuthenticatorId = authenticatorId
                persistedToken = newToken
                return Result.success(Unit)
            }
        }

        val mockEngine = MockEngine {
            respond(
                content = """
                {
                  "access_token": "new_token",
                  "refresh_token": "new_refresh",
                  "scope": "mmfaAuthn",
                  "authenticator_id": "uuidserver-authenticator-id-001",
                  "token_type": "bearer",
                  "expires_in": 3600
                }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json;charset=UTF-8")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "AuthenticatorClient",
            _authenticatorId = "tenant-id-001",
            _serverAuthenticatorId = "uuidserver-authenticator-id-001",
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
            assertEquals("tenant-id-001", callbackAuthenticatorId)
            assertEquals("new_token", persistedToken?.accessToken)
            assertEquals("uuidserver-authenticator-id-001", persistedToken?.additionalData?.get("authenticator_id"))
        }

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testNextTransaction_shouldReturnEmptyWhenServerAuthenticatorIdMissing() {
        val now = kotlin.time.Clock.System.now()
        val creationTime = now.toString()
        val lastActivityTime = now.toString()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/scim/Me") -> {
                    respond(
                        content = """
                        {
                          "meta": {
                            "location": "https://example.com/scim/Users/test_user_id",
                            "resourceType": "User"
                          },
                          "schemas": [
                            "urn:ietf:params:scim:schemas:core:2.0:User",
                            "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction"
                          ],
                          "id": "test_user_id",
                          "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction": {
                            "attributesPending": [
                              {
                                "dataType": "String",
                                "values": ["Approve transaction for authenticator A"],
                                "name": "mmfa.request.context.message",
                                "uri": "mmfa:request:context:message",
                                "transactionId": "transaction-a-001"
                              },
                              {
                                "dataType": "String",
                                "values": ["uuidserver-authenticator-id-A"],
                                "name": "mmfa.request.authenticator.id",
                                "uri": "mmfa:request:authenticator:id",
                                "transactionId": "transaction-a-001"
                              }
                            ],
                            "transactionsPending": [{
                              "authnPolicyAction": "POST",
                              "txnStatus": "PENDING",
                              "creationTime": "$creationTime",
                              "requestUrl": "https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=TRANSACTION-A-001",
                              "authnPolicyURI": "urn:ibm:security:authentication:asf:mmfa_response_userpresence",
                              "lastActivityTime": "$lastActivityTime",
                              "transactionId": "transaction-a-001"
                            }]
                          },
                          "userName": "testuser@example.com"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/scim+json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        }

        val httpClient = HttpClient(mockEngine)
        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending"),
            _clientId = "AuthenticatorClient",
            _authenticatorId = "tenant-id-A",
            _serverAuthenticatorId = null,
            httpClient = httpClient
        )

        runBlocking {
            val result = service.nextTransaction()

            assertTrue("nextTransaction should succeed", result.isSuccess)
            result.onSuccess { (transactions, count) ->
                assertEquals(1, count)
                assertTrue("Transactions should be empty when server authenticator id is missing", transactions.isEmpty())
            }
        }

        httpClient.close()
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testNextTransaction_byIdentifier_shouldReturnEmptyWhenOwnershipDoesNotMatch() {
        val now = kotlin.time.Clock.System.now()
        val creationTime = now.toString()
        val lastActivityTime = now.toString()

        val mockEngine = MockEngine { request ->
            when {
                request.url.encodedPath.contains("/scim/Me") -> {
                    respond(
                        content = """
                        {
                          "meta": {
                            "location": "https://example.com/scim/Users/test_user_id",
                            "resourceType": "User"
                          },
                          "schemas": [
                            "urn:ietf:params:scim:schemas:core:2.0:User",
                            "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction"
                          ],
                          "id": "test_user_id",
                          "urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction": {
                            "attributesPending": [
                              {
                                "dataType": "String",
                                "values": ["Approve transaction for authenticator B"],
                                "name": "mmfa.request.context.message",
                                "uri": "mmfa:request:context:message",
                                "transactionId": "transaction-b-001"
                              },
                              {
                                "dataType": "String",
                                "values": ["uuidserver-authenticator-id-B"],
                                "name": "mmfa.request.authenticator.id",
                                "uri": "mmfa:request:authenticator:id",
                                "transactionId": "transaction-b-001"
                              }
                            ],
                            "transactionsPending": [{
                              "authnPolicyAction": "POST",
                              "txnStatus": "PENDING",
                              "creationTime": "$creationTime",
                              "requestUrl": "https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=TRANSACTION-B-001",
                              "authnPolicyURI": "urn:ibm:security:authentication:asf:mmfa_response_userpresence",
                              "lastActivityTime": "$lastActivityTime",
                              "transactionId": "transaction-b-001"
                            }]
                          },
                          "userName": "testuser@example.com"
                        }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, "application/scim+json")
                    )
                }
                else -> respond("", HttpStatusCode.NotFound)
            }
        }

        val httpClient = HttpClient(mockEngine)
        val service = OnPremiseAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/mga/sps/oauth/oauth20/token"),
            _transactionUri = URL("https://example.com/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending,urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:attributesPending"),
            _clientId = "AuthenticatorClient",
            _authenticatorId = "tenant-id-A",
            _serverAuthenticatorId = "uuidserver-authenticator-id-A",
            httpClient = httpClient
        )

        runBlocking {
            val result = service.nextTransaction("transaction-b-001")

            assertTrue("nextTransaction should succeed", result.isSuccess)
            result.onSuccess { (transactions, count) ->
                assertEquals(1, count)
                assertTrue("Transactions should be empty when requested transaction belongs to another authenticator", transactions.isEmpty())
            }
        }

        httpClient.close()
    }
}

