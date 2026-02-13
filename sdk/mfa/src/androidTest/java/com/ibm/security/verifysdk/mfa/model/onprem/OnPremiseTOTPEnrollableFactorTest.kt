/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa.model.onprem

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.ibm.security.verifysdk.mfa.EnrollableType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

@RunWith(AndroidJUnit4::class)
class OnPremiseTOTPEnrollableFactorTest {

    private val testUri = URL("https://example.com/totp/secret")
    private val testEnabled = true

    @Test
    fun constructor_withUri_shouldCreateInstance() {
        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)

        // Then
        assertEquals(testUri, factor.uri)
        assertEquals(EnrollableType.TOTP, factor.type)
        assertEquals(testEnabled, factor.enabled)
    }

    @Test
    fun constructor_withDefaultType_shouldSetTOTP() {
        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)

        // Then
        assertEquals(EnrollableType.TOTP, factor.type)
    }

    @Test
    fun constructor_withExplicitType_shouldSetType() {
        // When
        val factor = OnPremiseTOTPEnrollableFactor(
            uri = testUri,
            type = EnrollableType.TOTP,
            enabled = testEnabled
        )

        // Then
        assertEquals(EnrollableType.TOTP, factor.type)
    }

    @Test
    fun constructor_withDifferentUri_shouldSetUri() {
        // Given
        val differentUri = URL("https://different.com/totp")

        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = differentUri, enabled = testEnabled)

        // Then
        assertEquals(differentUri, factor.uri)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val original = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.uri, copy.uri)
        assertEquals(original.type, copy.type)
        assertEquals(original.enabled, copy.enabled)
    }

    @Test
    fun copy_withModifiedUri_shouldUpdateOnlyUri() {
        // Given
        val original = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)
        val newUri = URL("https://new.com/totp")

        // When
        val modified = original.copy(uri = newUri)

        // Then
        assertEquals(newUri, modified.uri)
        assertEquals(original.type, modified.type)
        assertEquals(original.enabled, modified.enabled)
    }

    @Test
    fun copy_withModifiedType_shouldUpdateOnlyType() {
        // Given
        val original = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)

        // When
        val modified = original.copy(type = EnrollableType.TOTP)

        // Then
        assertEquals(original.uri, modified.uri)
        assertEquals(EnrollableType.TOTP, modified.type)
        assertEquals(original.enabled, modified.enabled)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val factor1 = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)
        val factor2 = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)

        // Then
        assertEquals(factor1, factor2)
    }

    @Test
    fun equals_withDifferentUri_shouldReturnFalse() {
        // Given
        val factor1 = OnPremiseTOTPEnrollableFactor(uri = URL("https://example1.com/totp"), enabled = testEnabled)
        val factor2 = OnPremiseTOTPEnrollableFactor(uri = URL("https://example2.com/totp"), enabled = testEnabled)

        // Then
        assertNotEquals(factor1, factor2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val factor1 = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)
        val factor2 = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)

        // Then
        assertEquals(factor1.hashCode(), factor2.hashCode())
    }

    @Test
    fun toString_shouldContainProperties() {
        // Given
        val factor = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)

        // When
        val result = factor.toString()

        // Then
        assert(result.contains("OnPremiseTOTPEnrollableFactor"))
        assert(result.contains("TOTP"))
    }

    @Test
    fun implementsEnrollableFactor_shouldHaveUriTypeAndEnabled() {
        // Given
        val factor = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)

        // Then
        assertNotNull(factor.uri)
        assertNotNull(factor.type)
        assertEquals(EnrollableType.TOTP, factor.type)
        assertEquals(testEnabled, factor.enabled)
    }

    @Test
    fun constructor_withHttpsUri_shouldSetUri() {
        // Given
        val httpsUri = URL("https://secure.example.com/totp/secret")

        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = httpsUri, enabled = testEnabled)

        // Then
        assertEquals(httpsUri, factor.uri)
        assertEquals("https", factor.uri.protocol)
    }

    @Test
    fun constructor_withHttpUri_shouldSetUri() {
        // Given
        val httpUri = URL("http://example.com/totp/secret")

        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = httpUri, enabled = testEnabled)

        // Then
        assertEquals(httpUri, factor.uri)
        assertEquals("http", factor.uri.protocol)
    }

    @Test
    fun constructor_withUriWithPort_shouldSetUri() {
        // Given
        val uriWithPort = URL("https://example.com:8443/totp/secret")

        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = uriWithPort, enabled = testEnabled)

        // Then
        assertEquals(uriWithPort, factor.uri)
        assertEquals(8443, factor.uri.port)
    }

    @Test
    fun constructor_withUriWithPath_shouldSetUri() {
        // Given
        val uriWithPath = URL("https://example.com/api/v1/totp/secret")

        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = uriWithPath, enabled = testEnabled)

        // Then
        assertEquals(uriWithPath, factor.uri)
        assertEquals("/api/v1/totp/secret", factor.uri.path)
    }

    @Test
    fun constructor_withUriWithQuery_shouldSetUri() {
        // Given
        val uriWithQuery = URL("https://example.com/totp/secret?param=value")

        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = uriWithQuery, enabled = testEnabled)

        // Then
        assertEquals(uriWithQuery, factor.uri)
        assertEquals("param=value", factor.uri.query)
    }

    @Test
    fun type_shouldAlwaysBeTOTP() {
        // Given
        val factor1 = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)
        val factor2 = OnPremiseTOTPEnrollableFactor(uri = URL("https://different.com/totp"), enabled = testEnabled)

        // Then
        assertEquals(EnrollableType.TOTP, factor1.type)
        assertEquals(EnrollableType.TOTP, factor2.type)
    }

    @Test
    fun multipleInstances_withSameUri_shouldBeEqual() {
        // Given
        val factor1 = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)
        val factor2 = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)
        val factor3 = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = testEnabled)

        // Then
        assertEquals(factor1, factor2)
        assertEquals(factor2, factor3)
        assertEquals(factor1, factor3)
    }

    @Test
    fun multipleInstances_withDifferentUri_shouldNotBeEqual() {
        // Given
        val factor1 = OnPremiseTOTPEnrollableFactor(uri = URL("https://example1.com/totp"), enabled = testEnabled)
        val factor2 = OnPremiseTOTPEnrollableFactor(uri = URL("https://example2.com/totp"), enabled = testEnabled)
        val factor3 = OnPremiseTOTPEnrollableFactor(uri = URL("https://example3.com/totp"), enabled = testEnabled)

        // Then
        assertNotEquals(factor1, factor2)
        assertNotEquals(factor2, factor3)
        assertNotEquals(factor1, factor3)
    }

    @Test
    fun enabled_withTrueValue_shouldSetEnabled() {
        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = true)

        // Then
        assertEquals(true, factor.enabled)
    }

    @Test
    fun enabled_withFalseValue_shouldSetEnabled() {
        // When
        val factor = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = false)

        // Then
        assertEquals(false, factor.enabled)
    }

    @Test
    fun copy_withModifiedEnabled_shouldUpdateOnlyEnabled() {
        // Given
        val original = OnPremiseTOTPEnrollableFactor(uri = testUri, enabled = true)

        // When
        val modified = original.copy(enabled = false)

        // Then
        assertEquals(false, modified.enabled)
        assertEquals(original.uri, modified.uri)
        assertEquals(original.type, modified.type)
    }
}


