/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.core.extension.baseUrl
import com.ibm.security.verifysdk.core.extension.replaceInPath
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

/**
 * Basic test cases for URL extension functions.
 */
@RunWith(AndroidJUnit4::class)
class UrlExtKtTest {

    @Test
    fun testReplaceInPathSimple() {
        val url = URL("https://example.com/api/v1/users")
        val result = url.replaceInPath("v1", "v2")
        
        assertEquals("https://example.com/api/v2/users", result.toString())
    }

    @Test
    fun testReplaceInPathMultipleOccurrences() {
        val url = URL("https://example.com/test/test/data")
        val result = url.replaceInPath("test", "prod")
        
        assertEquals("https://example.com/prod/prod/data", result.toString())
    }

    @Test
    fun testReplaceInPathNoMatch() {
        val url = URL("https://example.com/api/v1/users")
        val result = url.replaceInPath("v2", "v3")
        
        assertEquals("https://example.com/api/v1/users", result.toString())
    }

    @Test
    fun testReplaceInPathWithQuery() {
        val url = URL("https://example.com/api/v1/users?page=1")
        val result = url.replaceInPath("v1", "v2")
        
        assertTrue(result.toString().contains("/api/v2/users"))
        assertTrue(result.toString().contains("page=1"))
    }

    @Test
    fun testReplaceInPathWithFragment() {
        val url = URL("https://example.com/api/v1/users#section")
        val result = url.replaceInPath("v1", "v2")
        
        assertTrue(result.toString().contains("/api/v2/users"))
        assertTrue(result.toString().contains("#section"))
    }

    @Test
    fun testReplaceInPathEmptyReplacement() {
        val url = URL("https://example.com/api/v1/users")
        val result = url.replaceInPath("v1/", "")
        
        assertEquals("https://example.com/api/users", result.toString())
    }

    @Test
    fun testBaseUrlSimple() {
        val url = URL("https://example.com/api/v1/users")
        val result = url.baseUrl()
        
        assertEquals("https://example.com", result.toString())
    }

    @Test
    fun testBaseUrlWithPort() {
        val url = URL("https://example.com:8443/api/v1/users")
        val result = url.baseUrl()
        
        assertEquals("https://example.com:8443", result.toString())
    }

    @Test
    fun testBaseUrlWithQuery() {
        val url = URL("https://example.com/api/users?page=1")
        val result = url.baseUrl()
        
        assertEquals("https://example.com", result.toString())
        assertFalse(result.toString().contains("page=1"))
    }

    @Test
    fun testBaseUrlWithFragment() {
        val url = URL("https://example.com/api/users#section")
        val result = url.baseUrl()
        
        assertEquals("https://example.com", result.toString())
        assertFalse(result.toString().contains("#section"))
    }

    @Test
    fun testBaseUrlHttpProtocol() {
        val url = URL("http://example.com/api/users")
        val result = url.baseUrl()
        
        assertEquals("http://example.com", result.toString())
    }

    @Test
    fun testBaseUrlAlreadyBase() {
        val url = URL("https://example.com")
        val result = url.baseUrl()
        
        assertEquals("https://example.com", result.toString())
    }

    @Test
    fun testBaseUrlWithAuthentication() {
        val url = URL("https://user:pass@example.com/api/users")
        val result = url.baseUrl()
        
        assertTrue(result.toString().startsWith("https://"))
        assertTrue(result.toString().contains("example.com"))
    }

    @Test
    fun testReplaceInPathPreservesScheme() {
        val url = URL("https://example.com/api/v1/users")
        val result = url.replaceInPath("v1", "v2")
        
        assertEquals("https", result.protocol)
    }

    @Test
    fun testReplaceInPathPreservesAuthority() {
        val url = URL("https://example.com:8443/api/v1/users")
        val result = url.replaceInPath("v1", "v2")
        
        assertEquals("example.com:8443", result.authority)
    }
}
