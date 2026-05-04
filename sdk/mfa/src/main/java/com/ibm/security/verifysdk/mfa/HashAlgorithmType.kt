/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.mfa

import kotlinx.serialization.Serializable
import java.util.Locale

/**
 * Values indicating the type of hash algorithm to use. Instantiates an instance of the conforming
 * type from a string representation.
 *
 * The HashAlgorithmType enum represents the underlying hash algorithm (SHA-1, SHA-256, SHA-384,
 * SHA-512) in an abstract way, independent of the cryptographic operation (HMAC vs RSA). This
 * design allows the SDK to:
 * - Store a single enum value that represents the hash algorithm
 * - Convert to the appropriate format for different contexts (HMAC for TOTP, RSA for biometric)
 * - Support both symmetric (HMAC) and asymmetric (RSA) operations with the same enum
 *
 * The enum accepts multiple string formats via [fromString] (e.g., "SHA256", "HmacSHA256",
 * "RSASHA256", "SHA256withRSA") and provides conversion methods:
 * - [toString] returns the HMAC format (e.g., "HmacSHA256")
 * - [forSigning] returns the RSA signing format (e.g., "SHA256withRSA")
 * - [toIsvFormat] returns the IBM Verify SaaS format (e.g., "RSASHA256")
 *
 * @param rawValue The default string representation of the algorithm (HMAC format).
 */
@Serializable(with = HashAlgorithmTypeSerializer::class)
enum class HashAlgorithmType(private val rawValue: String) {
    /**
     * This hash algorithm isn’t considered cryptographically secure, but is provided for backward
     * compatibility with older services that require it.
     */
    SHA1("HmacSHA1"),

    /**
     * Secure Hashing Algorithm 2 (SHA-2) hashing with a 256-bit digest.
     */
    SHA256("HmacSHA256"),

    /**
     * Secure Hashing Algorithm 2 (SHA-2) hashing with a 384-bit digest.
     */
    SHA384("HmacSHA384"),

    /**
     * Secure Hashing Algorithm 2 (SHA-2) hashing with a 512-bit digest.
     */
    SHA512("HmacSHA512");

    override fun toString(): String {
        return rawValue
    }
    companion object {
        /**
         * Accepts "SHAx" and "HmacSHAx" (and other variations). The latter is required by Java itself
         * (https://docs.oracle.com/javase/7/docs/api/javax/crypto/Mac.html), whereas the first one
         * support Google's Key Uri Format
         * (https://github.com/google/google-authenticator/wiki/Key-Uri-Format#algorithm).
         */
        fun fromString(rawValue: String): HashAlgorithmType {
            return when (rawValue.uppercase(Locale.ROOT)) {
                "SHA1", "HMACSHA1", "RSASHA1", "SHA1WITHRSA" -> SHA1
                "SHA256", "HMACSHA256", "RSASHA256", "SHA256WITHRSA" -> SHA256
                "SHA384", "HMACSHA384", "RSASHA384", "SHA384WITHRSA" -> SHA384
                "SHA512", "HMACSHA512", "RSASHA512", "SHA512WITHRSA" -> SHA512
                else -> throw HashAlgorithmException.InvalidHash()
            }
        }

        /**
         * Converts a given raw hash algorithm name to its corresponding signing algorithm format.
         *
         *  @param rawValue The raw hash algorithm name as a string.
         *  @return The signing algorithm format corresponding to the provided raw hash algorithm name.
         *  @throws HashAlgorithmException.InvalidHash if the provided hash algorithm name is invalid.
         *
         * Normalize algorithm to value defined in
         * https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature
         */
        fun forSigning(rawValue: String): String {
            return when (rawValue.uppercase(Locale.ROOT)) {
                "SHA1", "HMACSHA1", "RSASHA1", "SHA1WITHRSA" -> "SHA1withRSA"
                "SHA256", "HMACSHA256", "RSASHA256", "SHA256WITHRSA" -> "SHA256withRSA"
                "SHA384", "HMACSHA384", "RSASHA384", "SHA384WITHRSA" -> "SHA384withRSA"
                "SHA512", "HMACSHA512", "RSASHA512", "SHA512WITHRSA" -> "SHA512withRSA"
                else -> throw HashAlgorithmException.InvalidHash()
            }
        }

        /**
         * Converts a given `HashAlgorithmType` to its corresponding IBM Verify format string.
         *
         * @param value The `HashAlgorithmType` to be converted.
         * @return The IBM Verify SaaS format string corresponding to the provided `HashAlgorithmType`.
         */
        internal fun toIsvFormat(value: HashAlgorithmType): String {
            return when (value) {
                SHA1 -> "RSASHA1"
                SHA256 -> "RSASHA256"
                SHA384 -> "RSASHA384"
                SHA512 -> "RSASHA512"
            }
        }
    }
}