/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */
@file:OptIn(ExperimentalUnsignedTypes::class)

package com.ibm.security.verifysdk.core.extension


import java.util.Base64

fun ByteArray.base64UrlEncode(): String {
    val base64Encoded = Base64.getUrlEncoder().encodeToString(this)
    return base64Encoded.trimEnd('=')
}

fun UByteArray.base64UrlEncode(): String {
    val base64Encoded = Base64.getUrlEncoder().encodeToString(this.toByteArray())
    return base64Encoded.trimEnd('=')
}

fun String.base64UrlEncode(): String {
    val base64Encoded = Base64.getUrlEncoder().encodeToString(this.toByteArray(Charsets.UTF_8))
    return base64Encoded.trimEnd('=')
}
