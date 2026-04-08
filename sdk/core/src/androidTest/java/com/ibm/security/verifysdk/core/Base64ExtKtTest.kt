/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.core.extension.base64UrlEncode
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Basic test cases for Base64 URL encoding extension functions.
 */
@RunWith(AndroidJUnit4::class)
class Base64ExtKtTest {

    @Test
    fun testByteArrayBase64UrlEncode() {
        val input = "Hello World".toByteArray()
        val encoded = input.base64UrlEncode()
        
        assertNotNull(encoded)
        assertFalse(encoded.contains("="))
        assertFalse(encoded.contains("+"))
        assertFalse(encoded.contains("/"))
    }

    @Test
    fun testByteArrayBase64UrlEncodeEmptyArray() {
        val input = ByteArray(0)
        val encoded = input.base64UrlEncode()
        
        assertEquals("", encoded)
    }

    @Test
    fun testUByteArrayBase64UrlEncode() {
        val input = ubyteArrayOf(72u, 101u, 108u, 108u, 111u) // "Hello"
        val encoded = input.base64UrlEncode()
        
        assertNotNull(encoded)
        assertFalse(encoded.contains("="))
    }

    @Test
    fun testStringBase64UrlEncode() {
        val input = "Hello World"
        val encoded = input.base64UrlEncode()
        
        assertNotNull(encoded)
        assertFalse(encoded.contains("="))
        assertTrue(encoded.length > 0)
    }

    @Test
    fun testStringBase64UrlEncodeEmptyString() {
        val input = ""
        val encoded = input.base64UrlEncode()
        
        assertEquals("", encoded)
    }

    @Test
    fun testStringBase64UrlEncodeSpecialCharacters() {
        val input = "Test@#$%^&*()"
        val encoded = input.base64UrlEncode()
        
        assertNotNull(encoded)
        assertFalse(encoded.contains("="))
        assertFalse(encoded.contains("+"))
        assertFalse(encoded.contains("/"))
    }

    @Test
    fun testStringBase64UrlEncodeUnicode() {
        val input = "Hello 世界 🌍"
        val encoded = input.base64UrlEncode()
        
        assertNotNull(encoded)
        assertFalse(encoded.contains("="))
        assertTrue(encoded.length > 0)
    }

    @Test
    fun testBase64UrlEncodeNoPadding() {
        // Test that padding characters are removed
        val input = "a" // This would normally produce padding
        val encoded = input.base64UrlEncode()
        
        assertFalse(encoded.endsWith("="))
    }

    @Test
    fun testBase64UrlEncodeConsistency() {
        val input = "Test String"
        val encoded1 = input.base64UrlEncode()
        val encoded2 = input.base64UrlEncode()
        
        assertEquals(encoded1, encoded2)
    }

    @Test
    fun testByteArrayAndStringEquivalence() {
        val text = "Hello"
        val encodedFromString = text.base64UrlEncode()
        val encodedFromBytes = text.toByteArray().base64UrlEncode()
        
        assertEquals(encodedFromString, encodedFromBytes)
    }
}
