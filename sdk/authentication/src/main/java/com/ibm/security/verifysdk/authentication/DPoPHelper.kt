/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
package com.ibm.security.verifysdk.authentication

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import org.jose4j.jwk.RsaJsonWebKey
import org.jose4j.jws.JsonWebSignature
import org.jose4j.jwt.JwtClaims
import org.jose4j.lang.JoseException
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAKeyGenParameterSpec

/**
 * Helper class for generating DPoP (Demonstrating Proof-of-Possession) tokens.
 *
 * DPoP is a mechanism for sender-constraining OAuth 2.0 tokens via a proof-of-possession mechanism
 * at the application layer. This class provides utilities to generate DPoP proof tokens that can be
 * used with OAuth 2.0 token requests and resource server requests.
 *
 * @since 3.0.13
 */
class DPoPHelper {

    companion object {
        private const val TAG = "DPoPHelper"
        
        /**
         * Default key alias used for DPoP key storage in Android KeyStore.
         */
        const val DEFAULT_KEY_ALIAS = "rsa-dpop-key.com.ibm.security.verifysdk.authentication"
        
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        private val keyStore: KeyStore by lazy {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply {
                load(null)
            }
        }

        /**
         * Generates a DPoP proof token for use in HTTP requests.
         *
         * @param htu The HTTP URI (without query and fragment parts) of the request.
         * @param htm The HTTP method of the request (e.g., "POST", "GET").
         * @param accessToken Optional access token to bind to the DPoP proof. When provided,
         *                    the hash of the access token (ath claim) will be included.
         * @param keyAlias The alias of the key to use from the Android KeyStore.
         *                 Defaults to [DEFAULT_KEY_ALIAS].
         * @return The DPoP proof token as a JWT string.
         * @throws RuntimeException if token generation fails.
         */
        @JvmStatic
        @JvmOverloads
        fun generateDPoPToken(
            htu: String,
            htm: String,
            accessToken: String? = null,
            keyAlias: String = DEFAULT_KEY_ALIAS
        ): String {
            return try {
                val jwtClaims = JwtClaims()
                jwtClaims.setGeneratedJwtId()
                jwtClaims.setIssuedAtToNow()
                jwtClaims.setClaim("htm", htm)
                jwtClaims.setClaim("htu", htu)

                // Add access token hash if provided
                accessToken?.let {
                    val ath = generateAccessTokenHash(it)
                    jwtClaims.setClaim("ath", ath)
                    Log.d(TAG, "Access token hash (ath): $ath")
                }

                val jws = JsonWebSignature()
                jws.payload = jwtClaims.toJson()
                jws.key = getRsaSigningKey(keyAlias)
                jws.algorithmHeaderValue = "RS256"
                jws.jwkHeader = RsaJsonWebKey(
                    keyStore.getCertificate(keyAlias).publicKey as RSAPublicKey
                )
                jws.setHeader("typ", "dpop+jwt")

                val jwt = jws.compactSerialization
                Log.d(TAG, "Generated DPoP token: $jwt")
                jwt
            } catch (e: JoseException) {
                throw RuntimeException("Failed to generate DPoP token", e)
            } catch (e: NoSuchAlgorithmException) {
                throw RuntimeException("Failed to generate DPoP token", e)
            }
        }

        /**
         * Generates the SHA-256 hash of an access token for the "ath" claim.
         *
         * @param accessToken The access token to hash.
         * @return Base64 URL-encoded hash of the access token.
         */
        private fun generateAccessTokenHash(accessToken: String): String {
            val bytes = accessToken.toByteArray(StandardCharsets.UTF_8)
            val messageDigest = MessageDigest.getInstance("SHA-256")
            messageDigest.update(bytes, 0, bytes.size)
            val digest = messageDigest.digest()
            return Base64.encodeToString(
                digest,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
        }

        /**
         * Retrieves or generates the RSA signing key from the Android KeyStore.
         *
         * @param keyAlias The alias of the key in the KeyStore.
         * @return The RSA private key for signing DPoP tokens.
         */
        private fun getRsaSigningKey(keyAlias: String): Key {
            if (keyStore.containsAlias(keyAlias)) {
                Log.d(TAG, "Key $keyAlias found in KeyStore")
            } else {
                val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
                    .build()

                val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA,
                    ANDROID_KEYSTORE
                )
                keyPairGenerator.initialize(keyGenParameterSpec)
                keyPairGenerator.generateKeyPair()
                Log.d(TAG, "Key $keyAlias generated")
            }

            return keyStore.getKey(keyAlias, null)
        }

        /**
         * Deletes the DPoP key from the Android KeyStore.
         * This can be useful for testing or when you want to generate a new key pair.
         *
         * @param keyAlias The alias of the key to delete. Defaults to [DEFAULT_KEY_ALIAS].
         */
        @JvmStatic
        @JvmOverloads
        fun deleteKey(keyAlias: String = DEFAULT_KEY_ALIAS) {
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
                Log.d(TAG, "Key $keyAlias deleted from KeyStore")
            }
        }

        /**
         * Checks if a DPoP key exists in the Android KeyStore.
         *
         * @param keyAlias The alias of the key to check. Defaults to [DEFAULT_KEY_ALIAS].
         * @return true if the key exists, false otherwise.
         */
        @JvmStatic
        @JvmOverloads
        fun hasKey(keyAlias: String = DEFAULT_KEY_ALIAS): Boolean {
            return keyStore.containsAlias(keyAlias)
        }
    }
}
