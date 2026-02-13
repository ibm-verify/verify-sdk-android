/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

package com.ibm.security.verifysdk.core.extension

import android.net.Uri
import java.net.URI
import java.net.URL


fun URL.replaceInPath(target: String, replacement: String): URL {
    val uri = this.toURI()
    val newPath = uri.path.replace(target, replacement)
    return URI(uri.scheme, uri.authority, newPath, uri.query, uri.fragment).toURL()
}


fun URL.baseUrl(): URL {
    try {
        val uriBuilder = Uri.Builder()
        uriBuilder.scheme((this.protocol))
            .encodedAuthority(this.authority)
        return URL(uriBuilder.build().toString())
    } catch (_: Exception) {
        return this
    }
}