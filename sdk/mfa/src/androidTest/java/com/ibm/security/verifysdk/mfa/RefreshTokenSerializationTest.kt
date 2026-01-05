/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import android.annotation.SuppressLint
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ibm.security.verifysdk.authentication.model.TokenInfo
import com.ibm.security.verifysdk.mfa.api.CloudAuthenticatorService
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
 * Test case to verify the fix for the serialization error:
 * "Serializing collections of different element types is not yet supported.
 * Selected serializers: [kotlin.String, kotlin.Boolean]"
 *
 * The fix uses buildJsonObject to manually construct JSON instead of relying on
 * automatic serialization of Map<String, Any> with mixed types.
 */
@RunWith(AndroidJUnit4::class)
class RefreshTokenSerializationTest {

    @Before
    fun setup() {
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        MFAAttributeInfo.init(appContext)
    }

    @SuppressLint("DenyListedBlockingApi")
    @Test
    fun testRefreshTokenWithMixedTypesSucceeds() {
        // This test verifies that refreshToken can now handle mixed types
        // by using buildJsonObject instead of Map<String, Any> serialization
        
        val mockEngine = MockEngine { request ->
            // Verify the request body contains the expected JSON structure
            val requestBody = when (val body = request.body) {
                is io.ktor.http.content.TextContent -> body.text
                else -> body.toString()
            }
            assertTrue("Request should contain refreshToken, got: $requestBody", requestBody.contains("refreshToken"))
            assertTrue("Request should contain attributes, got: $requestBody", requestBody.contains("attributes"))
            
            respond(
                content = """{"access_token":"new_access_token","refresh_token":"new_refresh_token","token_type":"Bearer","expires_in":3600}""",
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine)

        val service = CloudAuthenticatorService(
            _accessToken = "test_access_token",
            _refreshUri = URL("https://example.com/v1.0/authenticators/refresh"),
            _transactionUri = URL("https://example.com/v1.0/authenticators/transactions"),
            _authenticatorId = "test_authenticator_id"
        )

        // Call refreshToken with mixed-type attributes
        runBlocking {
            val result = service.refreshToken(
                refreshToken = "test_refresh_token",
                accountName = "test@example.com",
                pushToken = "test_push_token",
                additionalData = null,
                httpClient = httpClient
            )

            // Verify the result is successful
            if (result.isFailure) {
                result.onFailure { error ->
                    throw AssertionError("refreshToken failed with error: ${error.message}", error)
                }
            }
            
            assertTrue("refreshToken should succeed", result.isSuccess)
            
            result.onSuccess { tokenInfo ->
                assertEquals("new_access_token", tokenInfo.accessToken)
                assertEquals("new_refresh_token", tokenInfo.refreshToken)
            }
        }

        httpClient.close()
    }

    @Test
    fun testMFAAttributeInfoContainsMixedTypes() {
        // Verify that MFAAttributeInfo.dictionary() returns mixed types
        // This confirms the root cause that required the fix
        val attributes = MFAAttributeInfo.dictionary()
        
        var hasStringType = false
        var hasBooleanType = false
        
        attributes.values.forEach { value ->
            when (value) {
                is String -> hasStringType = true
                is Boolean -> hasBooleanType = true
            }
        }
        
        assertTrue("MFAAttributeInfo should contain String values", hasStringType)
        assertTrue("MFAAttributeInfo should contain Boolean values", hasBooleanType)
    }
}
