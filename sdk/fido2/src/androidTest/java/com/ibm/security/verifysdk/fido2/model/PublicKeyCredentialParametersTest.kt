package com.ibm.security.verifysdk.fido2.model

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.skyscreamer.jsonassert.JSONAssert

private val json = Json {
    encodeDefaults = true
    explicitNulls = false
    ignoreUnknownKeys = true
    isLenient = true
}

@RunWith(AndroidJUnit4::class)
class PublicKeyCredentialParametersTest {

    @Test
    fun testSerialization_withAlg() {
        val params = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            alg = 1L // Example COSEAlgorithmIdentifier
        )

        val jsonString = json.encodeToString(PublicKeyCredentialParameters.serializer(), params)
        val expectedJson = """{"type":"public-key","alg":1}"""
        JSONAssert.assertEquals(expectedJson, jsonString, false)
    }

    @Test
    fun testSerialization_withoutAlg() {
        val params = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            alg = null
        )

        val jsonString = json.encodeToString(PublicKeyCredentialParameters.serializer(), params)
        val expectedJson = """{"type":"public-key"}"""
        assertEquals(expectedJson, jsonString)
    }

    @Test
    fun testDeserialization_withAlg() {
        val jsonString = """{"type":"public-key","alg":1}"""
        val params = json.decodeFromString(PublicKeyCredentialParameters.serializer(), jsonString)

        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, params.type)
        assertEquals(1L, params.alg)
    }

    @Test
    fun testDeserialization_withoutAlg() {
        val jsonString = """{"type":"public-key"}"""
        val params = json.decodeFromString(PublicKeyCredentialParameters.serializer(), jsonString)

        assertEquals(PublicKeyCredentialType.PUBLIC_KEY, params.type)
        assertNull(params.alg)
    }

    @Test
    fun testEquality() {
        val params1 = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            alg = 1L
        )
        val params2 = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            alg = 1L
        )

        assertEquals(params1, params2)
    }

    @Test
    fun testInequality_differentType() {
        val params1 = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            alg = 1L
        )
        val params2 = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY, // Same type
            alg = 2L // Different alg
        )

        assertNotEquals(params1, params2)
    }

    @Test
    fun testInequality_differentAlg() {
        val params1 = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            alg = 1L
        )
        val params2 = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            alg = null // Different alg
        )

        assertNotEquals(params1, params2)
    }

    @Test
    fun testInequality_differentTypeAndAlg() {
        val params1 = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY,
            alg = 1L
        )
        val params2 = PublicKeyCredentialParameters(
            type = PublicKeyCredentialType.PUBLIC_KEY, // Same type
            alg = 2L // Different alg
        )

        assertNotEquals(params1, params2)
    }

}
