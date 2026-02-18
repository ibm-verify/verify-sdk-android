/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL

@RunWith(AndroidJUnit4::class)
class SignatureEnrollableFactorTest {

    @Test
    fun constructor_withAllParameters_shouldCreateInstance() {
        // Given
        val uri = URL("https://example.com/enroll")
        val type = EnrollableType.FINGERPRINT
        val enabled = true
        val algorithm = "SHA256"

        // When
        val factor = SignatureEnrollableFactor(
            uri = uri,
            type = type,
            enabled = enabled,
            algorithm = algorithm
        )

        // Then
        assertEquals(uri, factor.uri)
        assertEquals(type, factor.type)
        assertEquals(enabled, factor.enabled)
        assertEquals(algorithm, factor.algorithm)
    }

    @Test
    fun constructor_withFingerprintType_shouldCreateInstance() {
        // Given
        val uri = URL("https://example.com/fingerprint")
        val type = EnrollableType.FINGERPRINT
        val enabled = true
        val algorithm = "SHA256"

        // When
        val factor = SignatureEnrollableFactor(uri, type, enabled, algorithm)

        // Then
        assertEquals(EnrollableType.FINGERPRINT, factor.type)
    }

    @Test
    fun constructor_withFaceType_shouldCreateInstance() {
        // Given
        val uri = URL("https://example.com/face")
        val type = EnrollableType.FACE
        val enabled = true
        val algorithm = "SHA512"

        // When
        val factor = SignatureEnrollableFactor(uri, type, enabled, algorithm)

        // Then
        assertEquals(EnrollableType.FACE, factor.type)
    }

    @Test
    fun constructor_withUserPresenceType_shouldCreateInstance() {
        // Given
        val uri = URL("https://example.com/presence")
        val type = EnrollableType.USER_PRESENCE
        val enabled = true
        val algorithm = "SHA1"

        // When
        val factor = SignatureEnrollableFactor(uri, type, enabled, algorithm)

        // Then
        assertEquals(EnrollableType.USER_PRESENCE, factor.type)
    }

    @Test
    fun algorithm_withSHA1_shouldSetAlgorithm() {
        // Given
        val uri = URL("https://example.com")
        val algorithm = "SHA1"

        // When
        val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, true, algorithm)

        // Then
        assertEquals("SHA1", factor.algorithm)
    }

    @Test
    fun algorithm_withSHA256_shouldSetAlgorithm() {
        // Given
        val uri = URL("https://example.com")
        val algorithm = "SHA256"

        // When
        val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, true, algorithm)

        // Then
        assertEquals("SHA256", factor.algorithm)
    }

    @Test
    fun algorithm_withSHA384_shouldSetAlgorithm() {
        // Given
        val uri = URL("https://example.com")
        val algorithm = "SHA384"

        // When
        val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, true, algorithm)

        // Then
        assertEquals("SHA384", factor.algorithm)
    }

    @Test
    fun algorithm_withSHA512_shouldSetAlgorithm() {
        // Given
        val uri = URL("https://example.com")
        val algorithm = "SHA512"

        // When
        val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, true, algorithm)

        // Then
        assertEquals("SHA512", factor.algorithm)
    }

    @Test
    fun uri_withHttpsProtocol_shouldSetUri() {
        // Given
        val uri = URL("https://secure.example.com/enroll")

        // When
        val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, true, "SHA256")

        // Then
        assertEquals("https", factor.uri.protocol)
        assertEquals("secure.example.com", factor.uri.host)
        assertEquals("/enroll", factor.uri.path)
    }

    @Test
    fun uri_withHttpProtocol_shouldSetUri() {
        // Given
        val uri = URL("http://example.com/enroll")

        // When
        val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, true, "SHA256")

        // Then
        assertEquals("http", factor.uri.protocol)
    }

    @Test
    fun uri_withQueryParameters_shouldPreserveParameters() {
        // Given
        val uri = URL("https://example.com/enroll?param1=value1&param2=value2")

        // When
        val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, true, "SHA256")

        // Then
        assertEquals("param1=value1&param2=value2", factor.uri.query)
    }

    @Test
    fun implementsEnrollableFactor_shouldHaveUriTypeAndEnabled() {
        // Given
        val uri = URL("https://example.com")
        val factor: EnrollableFactor = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )

        // Then
        assertNotNull(factor.uri)
        assertNotNull(factor.type)
        assertEquals(true, factor.enabled)
    }

    @Test
    fun copy_shouldCreateNewInstanceWithSameValues() {
        // Given
        val uri = URL("https://example.com")
        val original = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val copy = original.copy()

        // Then
        assertEquals(original.uri, copy.uri)
        assertEquals(original.type, copy.type)
        assertEquals(original.enabled, copy.enabled)
        assertEquals(original.algorithm, copy.algorithm)
    }

    @Test
    fun copy_withModifiedUri_shouldUpdateOnlyUri() {
        // Given
        val originalUri = URL("https://example.com")
        val newUri = URL("https://newexample.com")
        val original = SignatureEnrollableFactor(
            uri = originalUri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val modified = original.copy(uri = newUri)

        // Then
        assertEquals(newUri, modified.uri)
        assertEquals(original.type, modified.type)
        assertEquals(original.enabled, modified.enabled)
        assertEquals(original.algorithm, modified.algorithm)
    }

    @Test
    fun copy_withModifiedType_shouldUpdateOnlyType() {
        // Given
        val uri = URL("https://example.com")
        val original = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val modified = original.copy(type = EnrollableType.FACE)

        // Then
        assertEquals(original.uri, modified.uri)
        assertEquals(EnrollableType.FACE, modified.type)
        assertEquals(original.enabled, modified.enabled)
        assertEquals(original.algorithm, modified.algorithm)
    }

    @Test
    fun copy_withModifiedAlgorithm_shouldUpdateOnlyAlgorithm() {
        // Given
        val uri = URL("https://example.com")
        val original = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val modified = original.copy(algorithm = "SHA512")

        // Then
        assertEquals(original.uri, modified.uri)
        assertEquals(original.type, modified.type)
        assertEquals(original.enabled, modified.enabled)
        assertEquals("SHA512", modified.algorithm)
    }

    @Test
    fun equals_withSameValues_shouldReturnTrue() {
        // Given
        val uri = URL("https://example.com")
        val factor1 = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )
        val factor2 = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )

        // Then
        assertEquals(factor1, factor2)
    }

    @Test
    fun hashCode_withSameValues_shouldReturnSameHashCode() {
        // Given
        val uri = URL("https://example.com")
        val factor1 = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )
        val factor2 = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )

        // Then
        assertEquals(factor1.hashCode(), factor2.hashCode())
    }

    @Test
    fun toString_shouldContainFactorInformation() {
        // Given
        val uri = URL("https://example.com")
        val factor = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val result = factor.toString()

        // Then
        assertNotNull(result)
        assert(result.contains("SignatureEnrollableFactor"))
    }

    @Test
    fun allEnrollableTypes_shouldBeSupported() {
        // Given
        val uri = URL("https://example.com")
        val types = listOf(
            EnrollableType.FINGERPRINT,
            EnrollableType.FACE,
            EnrollableType.USER_PRESENCE
        )

        // When/Then
        for (type in types) {
            val factor = SignatureEnrollableFactor(uri, type, true, "SHA256")
            assertEquals(type, factor.type)
        }
    }

    @Test
    fun allHashAlgorithms_shouldBeSupported() {
        // Given
        val uri = URL("https://example.com")
        val algorithms = listOf("SHA1", "SHA256", "SHA384", "SHA512")

        // When/Then
        for (algorithm in algorithms) {
            val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, true, algorithm)
            assertEquals(algorithm, factor.algorithm)
        }
    }

    @Test
    fun enabled_withTrueValue_shouldSetEnabled() {
        // Given
        val uri = URL("https://example.com")

        // When
        val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, true, "SHA256")

        // Then
        assertEquals(true, factor.enabled)
    }

    @Test
    fun enabled_withFalseValue_shouldSetEnabled() {
        // Given
        val uri = URL("https://example.com")

        // When
        val factor = SignatureEnrollableFactor(uri, EnrollableType.FINGERPRINT, false, "SHA256")

        // Then
        assertEquals(false, factor.enabled)
    }

    @Test
    fun copy_withModifiedEnabled_shouldUpdateOnlyEnabled() {
        // Given
        val uri = URL("https://example.com")
        val original = SignatureEnrollableFactor(
            uri = uri,
            type = EnrollableType.FINGERPRINT,
            enabled = true,
            algorithm = "SHA256"
        )

        // When
        val modified = original.copy(enabled = false)

        // Then
        assertEquals(original.uri, modified.uri)
        assertEquals(original.type, modified.type)
        assertEquals(false, modified.enabled)
        assertEquals(original.algorithm, modified.algorithm)
    }
}

