//
// Copyright contributors to the IBM Verify Authentication SDK for Android project
//
package com.ibm.security.verifysdk.authentication

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.net.toUri

/**
 * 'Proxy' activity to handle the attempt to get an authorization code. The activity
 * is started by [OAuthProvider] and launches Chrome Custom Tabs (CCT) to initiate the authorization
 * code (AZN) flow using Proof Key for Code Exchange (PKCE).
 *
 * Upon successful user authentication, the authorization code is extracted from the redirect and
 * returned to the calling activity. In case of an error or when the user has dismissed CCT, an
 * exception is returned.
 *
 * @since 3.0.0
 */
internal class AuthenticationActivity : ComponentActivity() {

    private val builder = CustomTabsIntent.Builder()
    private var url: String = ""
    private var code: String = ""
    private var hasAuthenticationStarted = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        url = intent.getStringExtra("url") ?: ""
        hasAuthenticationStarted = false
        code = ""
    }

    override fun onResume() {
        super.onResume()

        if (!hasAuthenticationStarted) {
            hasAuthenticationStarted = true
            launchCustomTab()
            return
        }

        if (code.isNotEmpty()) {
            setResult(RESULT_OK, Intent().apply {
                putExtra("code", code)
            })
        } else {
            setResult(RESULT_CANCELED, Intent())
        }
        finish()
    }

    private fun launchCustomTab() {
        val intent = builder.build().intent.apply {
            data = url.toUri()
            putExtra(Intent.EXTRA_REFERRER, ("android-app://${packageName}").toUri())
        }
        startActivity(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        intent.data?.getQueryParameter("code")?.let {
            code = it
        }
    }
}