/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core.extension

import com.ibm.security.verifysdk.core.helper.KeystoreHelper.hash
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.util.Locale

val camelRegex = "(?<=[a-zA-Z])[A-Z]".toRegex()
val snakeRegex = "_[a-zA-Z]".toRegex()

fun String.toNumberOrNull(): Number? {

    return this.toIntOrNull() ?: this.toLongOrNull() ?: this.toDoubleOrNull()
}

fun String.toNumberOrDefault(default: Number): Number {

    return this.toIntOrNull() ?: this.toLongOrNull() ?: this.toDoubleOrNull() ?: default
}

fun String.sha256(): String {
    return hash(this, "SHA-256")
}

fun String.camelToSnakeCase(): String {
    return camelRegex.replace(this) {
        "_${it.value}"
    }.lowercase(Locale.ROOT)
}

fun String.snakeToCamelCase(): String {
    return snakeRegex.replace(this) {
        it.value.substring(1).uppercase(Locale.ROOT)
    }
}

/**
 * Decodes a Base32 encoded string into a [ByteArray].
 *
 * This implementation is case-insensitive and supports optional padding.
 * It's based on the RFC 4648 standard.
 *
 * @receiver The Base32 encoded string.
 * @return The decoded byte array.
 * @throws IllegalArgumentException if the input string is not a valid Base32 string.
 */
fun String.decodeBase32(): ByteArray {
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    val lookup = alphabet.withIndex().associate { it.value to it.index.toLong() }

    val cleanInput = this.uppercase(Locale.ROOT).replace("=", "")
    val bytes = ByteArray(cleanInput.length * 5 / 8)
    var bitIndex = 0
    var byteIndex = 0
    var buffer = 0L

    for (char in cleanInput) {
        val value = lookup[char] ?: throw IllegalArgumentException("Invalid character in Base32 string: '$char'")
        buffer = (buffer shl 5) or value
        bitIndex += 5

        if (bitIndex >= 8) {
            bytes[byteIndex++] = (buffer shr (bitIndex - 8)).toByte()
            bitIndex -= 8
        }
    }
    return bytes
}


fun String.urlFormEncodedString(): String =
    URLEncoder.encode(this, StandardCharsets.UTF_8.toString())