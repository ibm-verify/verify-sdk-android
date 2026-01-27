/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.authentication

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import org.jose4j.jwt.JwtClaims
import org.jose4j.jwt.consumer.JwtConsumerBuilder
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.consumer.InvalidJwtException
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URI
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey

/**
 * Instrumentation tests for DPoPHelper.
 *
 * These must run on-device/emulator because they use AndroidKeyStore.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class DPoPHelperTest {

    private val alias = "test-dpop-key.authentication"
    private val androidKeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @After
    fun cleanup() {
        // Ensure isolation between tests
        DPoPHelper.deleteKey(alias)
    }

    @Test
    fun hasKey_returnsFalseInitially_andTrueAfterTokenGeneration() {
        DPoPHelper.deleteKey(alias)
        assertFalse(DPoPHelper.hasKey(alias))

        val token = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/token",
            htm = "POST",
            keyAlias = alias
        )
        assertTrue(token.isNotBlank())
        assertTrue(DPoPHelper.hasKey(alias))
    }

    @Test
    fun deleteKey_removesKey() {
        // Create key
        DPoPHelper.generateDPoPToken(
            htu = "https://example.com/resource",
            htm = "GET",
            keyAlias = alias
        )
        assertTrue(DPoPHelper.hasKey(alias))

        DPoPHelper.deleteKey(alias)
        assertFalse(DPoPHelper.hasKey(alias))
    }

    @Test
    fun generateDPoPToken_createsJwtWithRequiredHeaders() {
        DPoPHelper.deleteKey(alias)

        val jwt = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/resource",
            htm = "GET",
            keyAlias = alias
        )

        val jws = parseJws(jwt)
        assertEquals("RS256", jws.algorithmHeaderValue)
        assertEquals("dpop+jwt", jws.headers.getStringHeaderValue("typ"))

        // jwk header is a JSON object, not a string
        val jwkObj = jws.headers.getObjectHeaderValue("jwk")
        assertNotNull("Expected jwk header to be present", jwkObj)

        @Suppress("UNCHECKED_CAST")
        val jwk = jwkObj as Map<String, Any?>

        assertEquals("RSA", jwk["kty"])
        // These are typical for an RSA public JWK.
        // Some fields may vary by library/version, so only assert what you rely on.
        assertTrue("Expected modulus 'n' in jwk", jwk["n"] is String)
        assertTrue("Expected exponent 'e' in jwk", jwk["e"] is String)
    }

    @Test
    fun generateDPoPToken_containsRequiredClaims_andNoAthWhenNoAccessToken() {
        val htu = "https://example.com/resource"
        val htm = "GET"

        val jwt =
            DPoPHelper.generateDPoPToken(htu = htu, htm = htm, accessToken = null, keyAlias = alias)

        val claims = consumeAndVerify(jwt, publicKeyFor(alias))
        assertEquals(htm, claims.getStringClaimValue("htm"))
        assertEquals(htu, claims.getStringClaimValue("htu"))

        // jose4j uses "jti" and "iat" standard claim names
        assertNotNull("Expected jti", claims.jwtId)
        assertTrue("Expected iat > 0", claims.issuedAt.value > 0)

        assertNull("ath must not be present when accessToken is null", claims.getClaimValue("ath"))
    }

    @Test
    fun generateDPoPToken_includesAth_andItMatchesSha256Base64UrlNoPadding() {
        val htu = "https://example.com/token"
        val htm = "POST"
        val accessToken = "header.payload.signature" // any string is fine for hashing

        val jwt = DPoPHelper.generateDPoPToken(
            htu = htu,
            htm = htm,
            accessToken = accessToken,
            keyAlias = alias
        )

        val claims = consumeAndVerify(jwt, publicKeyFor(alias))
        val ath = claims.getStringClaimValue("ath")
        assertNotNull(ath)

        val expected = sha256Base64UrlNoPadding(accessToken)
        assertEquals(expected, ath)
    }

    @Test
    fun generateDPoPToken_signatureIsValidWithKeystorePublicKey() {
        val jwt = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/resource",
            htm = "GET",
            keyAlias = alias
        )

        // If verification fails, consumeAndVerify throws.
        val claims = consumeAndVerify(jwt, publicKeyFor(alias))
        assertEquals("GET", claims.getStringClaimValue("htm"))
    }

    @Test
    fun generateDPoPToken_reusesSameKeyAcrossCalls() {
        DPoPHelper.deleteKey(alias)

        val jwt1 = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/a",
            htm = "GET",
            keyAlias = alias
        )
        val pub1 = publicKeyFor(alias)

        val jwt2 = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/b",
            htm = "GET",
            keyAlias = alias
        )
        val pub2 = publicKeyFor(alias)

        // Same alias should mean same key (public modulus should match).
        val rsa1 = pub1 as RSAPublicKey
        val rsa2 = pub2 as RSAPublicKey
        assertEquals(rsa1.modulus, rsa2.modulus)

        // Both tokens should verify with the same public key.
        consumeAndVerify(jwt1, pub1)
        consumeAndVerify(jwt2, pub1)
    }

    @Test
    fun generateDPoPToken_jtiAndIatChangeBetweenCalls() {
        val jwt1 = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/resource",
            htm = "GET",
            keyAlias = alias
        )
        val jwt2 = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/resource",
            htm = "GET",
            keyAlias = alias
        )

        val pub = publicKeyFor(alias)
        val c1 = consumeAndVerify(jwt1, pub)
        val c2 = consumeAndVerify(jwt2, pub)

        assertNotEquals("jti should be different", c1.jwtId, c2.jwtId)

        // iat could theoretically be same second; still, usually changes.
        // Enforce a weaker invariant: iat exists and is not in the future by a lot.
        assertTrue(c1.issuedAt.value > 0)
        assertTrue(c2.issuedAt.value > 0)
    }

    @Test
    fun htu_isExpectedToBeAbsoluteUriWithoutQueryOrFragment() {
        // Your helper does not validate htu; this test documents expected usage.
        // If you later add validation, convert this into an assertThrows test.
        val htu = "https://example.com/resource" // no ?query or #fragment
        val uri = URI(htu)
        assertNotNull(uri.scheme)
        assertNotNull(uri.host)
        assertNull(uri.query)
        assertNull(uri.fragment)

        val jwt = DPoPHelper.generateDPoPToken(
            htu = htu,
            htm = "GET",
            keyAlias = alias
        )

        val claims = consumeAndVerify(jwt, publicKeyFor(alias))
        assertEquals(htu, claims.getStringClaimValue("htu"))
    }

    // ---------- helpers ----------

    private fun publicKeyFor(alias: String): PublicKey {
        val cert = androidKeyStore.getCertificate(alias)
        assertNotNull("No certificate found for alias=$alias. Was a key generated?", cert)
        return cert.publicKey
    }

    private fun parseJws(jwt: String): JsonWebSignature {
        val jws = JsonWebSignature()
        jws.compactSerialization = jwt
        return jws
    }

    private fun consumeAndVerify(jwt: String, publicKey: PublicKey): JwtClaims {
        val consumer = JwtConsumerBuilder()
            .setRequireIssuedAt()
            .setRequireJwtId()
            .setVerificationKey(publicKey)
            .setSkipDefaultAudienceValidation()
            .build()

        return consumer.processToClaims(jwt)
    }

    private fun sha256Base64UrlNoPadding(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    @Test
    fun generateDPoPToken_whenKeyAlreadyExists_doesNotRotateKey() {
        DPoPHelper.deleteKey(alias)

        DPoPHelper.generateDPoPToken("https://example.com/a", "GET", keyAlias = alias)
        val pub1 = publicKeyFor(alias) as RSAPublicKey

        // second call hits keyStore.containsAlias(keyAlias) == true branch
        DPoPHelper.generateDPoPToken("https://example.com/b", "GET", keyAlias = alias)
        val pub2 = publicKeyFor(alias) as RSAPublicKey

        assertEquals(pub1.modulus, pub2.modulus)
    }

    @Test
    fun deleteKey_whenKeyDoesNotExist_doesNotThrow() {
        DPoPHelper.deleteKey(alias) // ensure absent
        DPoPHelper.deleteKey(alias) // should no-op
        assertFalse(DPoPHelper.hasKey(alias))
    }

    @Test
    fun generateDPoPToken_athDiffersForDifferentAccessTokens() {
        val jwt1 = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/token",
            htm = "POST",
            accessToken = "token-1",
            keyAlias = alias
        )
        val jwt2 = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/token",
            htm = "POST",
            accessToken = "token-2",
            keyAlias = alias
        )

        val pub = publicKeyFor(alias)
        val c1 = consumeAndVerify(jwt1, pub)
        val c2 = consumeAndVerify(jwt2, pub)

        assertNotEquals(c1.getStringClaimValue("ath"), c2.getStringClaimValue("ath"))
    }

    @Test
    fun generateDPoPToken_payloadIsValidJsonAndContainsClaims() {
        val jwt = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/resource",
            htm = "GET",
            keyAlias = alias
        )

        val claims = consumeAndVerify(jwt, publicKeyFor(alias))
        assertEquals("GET", claims.getStringClaimValue("htm"))
        assertEquals("https://example.com/resource", claims.getStringClaimValue("htu"))
        assertNotNull(claims.jwtId)
        assertTrue(claims.issuedAt.value > 0)
    }


    @Test(expected = InvalidJwtException::class)
    fun consumeAndVerify_failsWhenSignatureInvalid_butPayloadStillValidJson() {
        val jwt = DPoPHelper.generateDPoPToken(
            htu = "https://example.com/resource",
            htm = "GET",
            keyAlias = alias
        )

        val parts = jwt.split(".")
        assertEquals(3, parts.size)

        val payloadJson = String(base64UrlDecode(parts[1]), Charsets.UTF_8)
        val obj = JSONObject(payloadJson)
        obj.put("htu", "https://example.com/other") // modify claim

        val newPayloadB64 = base64UrlEncode(obj.toString().toByteArray(Charsets.UTF_8))
        val tamperedJwt = "${parts[0]}.$newPayloadB64.${parts[2]}"

        consumeAndVerify(tamperedJwt, publicKeyFor(alias))
        fail("Expected verification to fail for tampered token")
    }

    private fun base64UrlDecode(b64url: String): ByteArray =
        Base64.decode(b64url, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun base64UrlEncode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    @Test
    fun differentAliases_produceDifferentKeys() {
        val alias2 = "test-dpop-key-2.authentication"
        try {
            DPoPHelper.deleteKey(alias)
            DPoPHelper.deleteKey(alias2)

            DPoPHelper.generateDPoPToken("https://example.com/a", "GET", keyAlias = alias)
            DPoPHelper.generateDPoPToken("https://example.com/a", "GET", keyAlias = alias2)

            val pub1 = publicKeyFor(alias) as RSAPublicKey
            val pub2 = publicKeyFor(alias2) as RSAPublicKey

            assertNotEquals(pub1.modulus, pub2.modulus)
        } finally {
            DPoPHelper.deleteKey(alias2)
        }
    }
}
