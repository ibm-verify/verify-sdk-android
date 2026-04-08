//
// Copyright contributors to the IBM Verify Authentication SDK for Android project
//
package com.ibm.security.verifysdk.authentication

import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Proof Key for Code Exchange (PKCE) by OAuth 2.0 public clients.
 *
 * Where an OpenID Connect service provider has configured PKCE for authorization code-flow
 * operations, generate a code verifier and code challenge.
 *
 * For example:
 * <pre>
 * {@code
 *  val codeVerifier = PKCE.generateCodeVerifier()
 *  val codeChallenge = PKCE.generateCodeChallenge(codeVerifier)
 *
 *  print("SHA256 hash of codeVerifier: $codeChallenge")
 * }
 * </pre>
 *
 * @since 3.0.0
 */
@Suppress("unused")
class PKCEHelper {

    companion object {

        /**
         * Generates a cryptographically random string that is used to correlate the authorization
         * request to the token request.
         *
         * @return  Cryptographically random string
         * @since 3.0.0
         */
        @JvmStatic
        fun generateCodeVerifier(): String {

            val secureRandom = SecureRandom()
            val code = ByteArray(64)
            secureRandom.nextBytes(code)
            return Base64.encodeToString(
                code,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
        }

        /**
         * A challenge derived from the code verifier that is sent in the authorization request, to
         * be verified against later.
         *
         * @param codeVerifier: A cryptographically random string.
         * @return  Base-64 URL encoded string
         * @since 3.0.0
         */
        @JvmStatic
        fun generateCodeChallenge(codeVerifier: String): String {
            val bytes = codeVerifier.toByteArray(StandardCharsets.UTF_8)
            val messageDigest = MessageDigest.getInstance("SHA-256")
            messageDigest.update(bytes, 0, bytes.size)
            val digest = messageDigest.digest()
            return Base64.encodeToString(
                digest,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
        }
    }
}