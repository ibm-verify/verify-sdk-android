/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.api

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.lang.reflect.InvocationTargetException
import java.net.URL

private fun OnPremiseAuthenticatorService.invokeCreateUpdateUrl(transactionUri: URL): URL {
    val method = OnPremiseAuthenticatorService::class.java
        .getDeclaredMethod("createUpdateUrl", URL::class.java)
    method.isAccessible = true
    return try {
        method.invoke(this, transactionUri) as URL
    } catch (e: InvocationTargetException) {
        throw e.cause ?: e
    }
}

@RunWith(AndroidJUnit4::class)
class CreateUpdateUrlTest {

    private lateinit var service: OnPremiseAuthenticatorService

    @Before
    fun setup() {
        val mockEngine = MockEngine { respond("", HttpStatusCode.OK) }
        service = OnPremiseAuthenticatorService(
            _accessToken = "token",
            _refreshUri = URL("https://example.com/refresh"),
            _transactionUri = URL("https://example.com/scim/Me"),
            _clientId = "client",
            _authenticatorId = "auth-id",
            httpClient = HttpClient(mockEngine)
        )
    }

    // -----------------------------------------------------------------------
    // Fixed query parameter
    // -----------------------------------------------------------------------

    @Test
    fun testAttributesQueryParameter_isAlwaysAppended() {
        val result = service.invokeCreateUpdateUrl(URL("https://example.com/scim/Me"))

        // Uri.Builder.appendQueryParameter() percent-encodes ':' in the value, so
        // URL.getQuery() returns the encoded form. Decode before comparing.
        val decoded = java.net.URLDecoder.decode(result.query, "UTF-8")
        assertEquals(
            "attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:authenticators",
            decoded
        )
    }

    @Test
    fun testAttributesQueryParameter_exactValue() {
        val result = service.invokeCreateUpdateUrl(URL("https://example.com/scim/Me"))

        // Decode before checking for the plain-text URN.
        val decoded = java.net.URLDecoder.decode(result.query, "UTF-8")
        assertTrue(
            "Query must contain the SCIM authenticators attribute URN",
            decoded.contains("urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Authenticator:authenticators")
        )
    }

    // -----------------------------------------------------------------------
    // Scheme preservation
    // -----------------------------------------------------------------------

    @Test
    fun testHttpsScheme_isPreserved() {
        assertEquals(
            "https",
            service.invokeCreateUpdateUrl(URL("https://example.com/scim/Me")).protocol
        )
    }

    @Test
    fun testHttpScheme_isPreserved() {
        assertEquals(
            "http",
            service.invokeCreateUpdateUrl(URL("http://onprem.local/scim/Me")).protocol
        )
    }

    // -----------------------------------------------------------------------
    // Authority (host + optional port)
    // -----------------------------------------------------------------------

    @Test
    fun testHost_isPreserved() {
        assertEquals(
            "example.com",
            service.invokeCreateUpdateUrl(URL("https://example.com/scim/Me")).host
        )
    }

    @Test
    fun testCustomPort_isPreserved() {
        val result = service.invokeCreateUpdateUrl(URL("https://onprem.local:9443/scim/Me"))

        assertEquals("onprem.local", result.host)
        assertEquals(9443, result.port)
    }

    @Test
    fun testDefaultPort_remainsUnset() {
        assertEquals(-1, service.invokeCreateUpdateUrl(URL("https://example.com/scim/Me")).port)
    }

    // -----------------------------------------------------------------------
    // Path — taken from transactionUri.path, leading slash stripped
    // -----------------------------------------------------------------------

    @Test
    fun testPath_isPreserved() {
        assertEquals(
            "/scim/Me",
            service.invokeCreateUpdateUrl(URL("https://example.com/scim/Me")).path
        )
    }

    @Test
    fun testPath_withDeepSegments() {
        assertEquals(
            "/mga/scim/v2/Users/Me",
            service.invokeCreateUpdateUrl(URL("https://example.com/mga/scim/v2/Users/Me")).path
        )
    }

    /**
     * java.net.URL.getPath() always returns a leading '/'. trimStart('/') in the implementation
     * prevents appendEncodedPath from doubling it into "https://example.com//scim/Me".
     */
    @Test
    fun testNoDoubleSlash_pathAlreadyHasLeadingSlash() {
        val url = service.invokeCreateUpdateUrl(URL("https://example.com/scim/Me")).toString()

        assertFalse(
            "Path-derived leading slash must not be doubled after the host",
            url.substring("https://".length).contains("//")
        )
    }

    // -----------------------------------------------------------------------
    // Query from transactionUri — must NOT be copied, only the fixed one is present
    // -----------------------------------------------------------------------

    @Test
    fun testQueryFromTransactionUri_isNotCopied() {
        val uri =
            URL("https://example.com/scim/Me?attributes=urn:ietf:params:scim:schemas:extension:isam:1.0:MMFA:Transaction:transactionsPending")

        val result = service.invokeCreateUpdateUrl(uri)
        val decoded = java.net.URLDecoder.decode(result.query, "UTF-8")

        assertFalse(
            "Query from transactionUri must not appear in the update URL",
            decoded.contains("transactionsPending")
        )
        assertTrue(
            "Only the Authenticator attributes URN must be in the query",
            decoded.contains("MMFA:Authenticator:authenticators")
        )
    }

    // -----------------------------------------------------------------------
    // Full URL shape
    // -----------------------------------------------------------------------

    @Test
    fun testFullUrl_shape() {
        val url = service.invokeCreateUpdateUrl(URL("https://example.com/scim/Me")).toString()

        assertTrue(
            "Result must start with https://example.com/scim/Me",
            url.startsWith("https://example.com/scim/Me")
        )
        assertTrue(
            "Result must contain the attributes query parameter",
            url.contains("attributes=")
        )
    }
}
