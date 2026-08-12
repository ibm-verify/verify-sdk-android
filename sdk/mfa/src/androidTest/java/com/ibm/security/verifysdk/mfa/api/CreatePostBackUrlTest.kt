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

private fun OnPremiseAuthenticatorService.invokeCreatePostBackUrl(
    transactionRequestUrl: URL,
    verificationInfoLocation: String
): URL {
    val method = OnPremiseAuthenticatorService::class.java
        .getDeclaredMethod("createPostBackUrl", URL::class.java, String::class.java)
    method.isAccessible = true
    return try {
        method.invoke(this, transactionRequestUrl, verificationInfoLocation) as URL
    } catch (e: InvocationTargetException) {
        throw e.cause ?: e
    }
}

@RunWith(AndroidJUnit4::class)
class CreatePostBackUrlTest {

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
    // Basic construction
    // -----------------------------------------------------------------------

    @Test
    fun testSimplePath_schemeAndAuthorityPreserved() {
        val base = URL("https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=TX001")
        val location = "mga/sps/mmfa/user/mgmt/verify/12345"

        val result = service.invokeCreatePostBackUrl(base, location)

        assertEquals("https", result.protocol)
        assertEquals("example.com", result.host)
        assertEquals("/mga/sps/mmfa/user/mgmt/verify/12345", result.path)
    }

    @Test
    fun testResultUrl_toStringMatchesSchemeHostPath() {
        val base = URL("https://example.com/mga/sps/apiauthsvc")
        val location = "verify/abc"

        val result = service.invokeCreatePostBackUrl(base, location)

        assertTrue(
            "URL must start with https://example.com",
            result.toString().startsWith("https://example.com")
        )
        assertTrue(
            "URL must contain the location segment",
            result.toString().contains("verify/abc")
        )
    }

    // -----------------------------------------------------------------------
    // Scheme handling
    // -----------------------------------------------------------------------

    @Test
    fun testHttpScheme_isPreserved() {
        val base = URL("http://onprem.local/mga/sps/apiauthsvc")

        val result = service.invokeCreatePostBackUrl(base, "path/to/resource")

        assertEquals("http", result.protocol)
    }

    @Test
    fun testHttpsScheme_isPreserved() {
        val base = URL("https://secure.example.com/mga/sps/apiauthsvc")

        val result = service.invokeCreatePostBackUrl(base, "path/to/resource")

        assertEquals("https", result.protocol)
    }

    // -----------------------------------------------------------------------
    // Authority (host + optional port)
    // -----------------------------------------------------------------------

    @Test
    fun testCustomPort_isPreservedInAuthority() {
        val base = URL("https://onprem.local:9443/mga/sps/apiauthsvc")

        val result = service.invokeCreatePostBackUrl(base, "verify/session")

        assertEquals("onprem.local", result.host)
        assertEquals(9443, result.port)
    }

    @Test
    fun testDefaultPort_notDuplicated() {
        val base = URL("https://example.com/mga/sps/apiauthsvc")

        val result = service.invokeCreatePostBackUrl(base, "verify/session")

        assertEquals(-1, result.port)
        assertEquals("example.com", result.host)
    }

    // -----------------------------------------------------------------------
    // Path construction — no double-slash
    // -----------------------------------------------------------------------

    @Test
    fun testNoDoubleSlash_whenLocationHasNoLeadingSlash() {
        val base = URL("https://example.com/mga/sps/apiauthsvc")

        val result = service.invokeCreatePostBackUrl(base, "mga/sps/mmfa/user/mgmt/verify/txn-001")

        assertFalse(
            "Result URL must not contain a double-slash after the scheme",
            result.toString().substring("https://".length).contains("//")
        )
    }

    /**
     * Regression test: [createPostBackUrl] must strip the leading '/' from
     * [verificationInfoLocation] before calling [android.net.Uri.Builder.appendEncodedPath].
     * Without the strip, appendEncodedPath inserts its own separator AND keeps the literal '/'
     * producing "https://example.com//my/path" — the double-slash observed in production.
     */
    @Test
    fun testNoDoubleSlash_whenLocationHasLeadingSlash() {
        val base = URL("https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=TX001")

        val result = service.invokeCreatePostBackUrl(base, "/my/path")

        assertFalse(
            "Leading slash in location must not produce a double-slash after the host",
            result.toString().substring("https://".length).contains("//")
        )
        assertEquals("/my/path", result.path)
    }

    // -----------------------------------------------------------------------
    // Deep / multi-segment paths
    // -----------------------------------------------------------------------

    @Test
    fun testDeepPath_allSegmentsPresent() {
        val base = URL("https://example.com/apiauthsvc")

        val result = service.invokeCreatePostBackUrl(
            base,
            "mga/sps/mmfa/user/mgmt/verify/deeply/nested/resource"
        )

        assertTrue(result.path.endsWith("mga/sps/mmfa/user/mgmt/verify/deeply/nested/resource"))
    }

    // -----------------------------------------------------------------------
    // Query string in base URL — must NOT be carried over
    // -----------------------------------------------------------------------

    @Test
    fun testQueryParameters_fromBaseUrl_areNotCopied() {
        val base = URL("https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=TX-XYZ&foo=bar")

        val result = service.invokeCreatePostBackUrl(base, "verify/result")

        assertEquals(null, result.query)
    }

    // -----------------------------------------------------------------------
    // Authority from base URL — base path is discarded
    // -----------------------------------------------------------------------

    @Test
    fun testBaseUrlPath_isNotCopied_onlyAuthorityUsed() {
        val base = URL("https://example.com/some/ignored/path")

        val result = service.invokeCreatePostBackUrl(base, "new/location")

        assertFalse(
            "Base URL path must not appear in the result",
            result.path.contains("some/ignored/path")
        )
        assertTrue(
            "Result must contain the verificationInfoLocation",
            result.path.contains("new/location")
        )
    }

    // -----------------------------------------------------------------------
    // Leading-slash location — correct behaviour after trimStart('/') fix
    // -----------------------------------------------------------------------

    /** Counterpart of [testSimplePath_schemeAndAuthorityPreserved]. */
    @Test
    fun testLeadingSlash_schemeAndHostStillCorrect() {
        val base = URL("https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=TX001")

        val result = service.invokeCreatePostBackUrl(base, "/mga/sps/mmfa/user/mgmt/verify/12345")

        assertEquals("https", result.protocol)
        assertEquals("example.com", result.host)
        assertEquals("/mga/sps/mmfa/user/mgmt/verify/12345", result.path)
    }

    /** Counterpart of [testHttpScheme_isPreserved]. */
    @Test
    fun testLeadingSlash_httpSchemeIsPreserved() {
        val result = service.invokeCreatePostBackUrl(
            URL("http://onprem.local/mga/sps/apiauthsvc"),
            "/path/to/resource"
        )

        assertEquals("http", result.protocol)
        assertEquals("/path/to/resource", result.path)
    }

    /** Counterpart of [testHttpsScheme_isPreserved]. */
    @Test
    fun testLeadingSlash_httpsSchemeIsPreserved() {
        val result = service.invokeCreatePostBackUrl(
            URL("https://secure.example.com/mga/sps/apiauthsvc"),
            "/path/to/resource"
        )

        assertEquals("https", result.protocol)
        assertEquals("/path/to/resource", result.path)
    }

    /** Counterpart of [testCustomPort_isPreservedInAuthority]. */
    @Test
    fun testLeadingSlash_customPortIsPreserved() {
        val result = service.invokeCreatePostBackUrl(
            URL("https://onprem.local:9443/mga/sps/apiauthsvc"),
            "/verify/session"
        )

        assertEquals("onprem.local", result.host)
        assertEquals(9443, result.port)
        assertEquals("/verify/session", result.path)
    }

    /** Counterpart of [testDeepPath_allSegmentsPresent]. */
    @Test
    fun testLeadingSlash_deepPathSegmentsStillPresent() {
        val result = service.invokeCreatePostBackUrl(
            URL("https://example.com/apiauthsvc"),
            "/mga/sps/mmfa/user/mgmt/verify/deeply/nested/resource"
        )

        assertEquals("/mga/sps/mmfa/user/mgmt/verify/deeply/nested/resource", result.path)
    }

    /** Counterpart of [testQueryParameters_fromBaseUrl_areNotCopied]. */
    @Test
    fun testLeadingSlash_queryParametersFromBaseUrlAreNotCopied() {
        val result = service.invokeCreatePostBackUrl(
            URL("https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=TX-XYZ&foo=bar"),
            "/verify/result"
        )

        assertEquals(null, result.query)
        assertEquals("/verify/result", result.path)
    }

    /**
     * Full-URL string check for the production scenario from the bug report:
     *   base     https://mmfa-mobile.securitypoc.com/mga/sps/apiauthsvc?StateId=…
     *   location /mga/sps/apiauthsvc?StateId=…   (leading slash from server)
     * Expected:  https://mmfa-mobile.securitypoc.com/mga/sps/…  (single slash)
     * Buggy was: https://mmfa-mobile.securitypoc.com//mga/sps/… (double slash)
     */
    @Test
    fun testLeadingSlash_noDoubleSlashInToString() {
        val result = service.invokeCreatePostBackUrl(
            URL("https://example.com/mga/sps/apiauthsvc?MmfaTransactionId=TX001"),
            "/my/path"
        )

        val url = result.toString()
        assertFalse("Leading slash must not produce '//my' in the result URL", url.contains("//my"))
        assertTrue(
            "Result must start with https://example.com/my/path",
            url.startsWith("https://example.com/my/path")
        )
    }
}
