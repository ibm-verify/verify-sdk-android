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
 * @param rawValue The name of the algorithm.
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
                else -> throw HashAlgorithmError.InvalidHash
            }
        }

        /**
         * Converts a given raw hash algorithm name to its corresponding signing algorithm format.
         *
         *  @param rawValue The raw hash algorithm name as a string.
         *  @return The signing algorithm format corresponding to the provided raw hash algorithm name.
         *  @throws HashAlgorithmError.InvalidHash if the provided hash algorithm name is invalid.
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
                else -> throw HashAlgorithmError.InvalidHash
            }
        }

        /**
         * Converts a given `HashAlgorithmType` to its corresponding IBM Verify format string.
         *
         * @param value The `HashAlgorithmType` to be converted.
         * @return The ISV format string corresponding to the provided `HashAlgorithmType`.
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