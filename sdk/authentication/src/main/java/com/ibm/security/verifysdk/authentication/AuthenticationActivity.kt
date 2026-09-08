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
 * Proxy activity that manages the browser-based authorization code flow.
 *
 * Started by [OAuthProvider.authorizeWithBrowser], this activity launches Chrome Custom Tabs (CCT)
 * to perform the OAuth 2.0 authorization code flow, optionally with Proof Key for Code Exchange
 * (PKCE). It acts as the redirect target for the CCT session and extracts the authorization code
 * from the callback URI before returning control to the caller.
 *
 * ## Intent extras (input)
 * | Key                | Type      | Description                                                       |
 * |--------------------|-----------|-------------------------------------------------------------------|
 * | `url`              | `String`  | The fully-built authorization URI to open in Chrome Custom Tabs.  |
 * | `ephemeralSession` | `Boolean` | When `true`, opens CCT in ephemeral (incognito) mode via          |
 * |                    |           | [CustomTabsIntent.Builder.setEphemeralBrowsingEnabled], preventing |
 * |                    |           | reuse of existing browser session cookies. Defaults to `false`.   |
 *
 * ## Result
 * - **`RESULT_OK`** — authorization succeeded; the `code` string extra contains the authorization
 *   code to exchange for tokens via [OAuthProvider.authorize].
 * - **`RESULT_CANCELED`** — the user dismissed CCT or the redirect did not carry a `code`
 *   parameter.
 *
 * @since 3.0.0
 */
class AuthenticationActivity : ComponentActivity() {

    private var url: String = ""
    private var code: String = ""
    private var ephemeralSession: Boolean = false
    private var hasAuthenticationStarted = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        url = intent.getStringExtra("url") ?: ""
        ephemeralSession = intent.getBooleanExtra("ephemeralSession", false)
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
        val customTabsIntent = CustomTabsIntent.Builder()
            .setEphemeralBrowsingEnabled(ephemeralSession)
            .build()
        val launchIntent: Intent = customTabsIntent.intent
        launchIntent.data = url.toUri()
        launchIntent.putExtra(Intent.EXTRA_REFERRER, Uri.parse("android-app://${packageName}"))
        startActivity(launchIntent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)

        intent.data?.getQueryParameter("code")?.let {
            code = it
        }
    }
}