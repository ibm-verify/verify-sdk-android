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
 * Started by [OAuthProvider.authorizeWithBrowser], this activity launches a Custom Tabs session
 * to perform the OAuth 2.0 authorization code flow, optionally with Proof Key for Code Exchange
 * (PKCE). It acts as the redirect target for the Custom Tabs session and extracts the
 * authorization code from the callback URI before returning control to the caller.
 *
 * The Custom Tabs protocol is supported by Google Chrome, Mozilla Firefox, and Microsoft Edge.
 * The device's default browser is used if it supports Custom Tabs; otherwise the user is prompted
 * to choose. Not all browsers that support Custom Tabs implement the redirect contract required
 * to return control to the app; only the browsers listed above are verified to work correctly.
 *
 * ## Intent extras (input)
 * | Key                | Type      | Description                                                            |
 * |--------------------|-----------|------------------------------------------------------------------------|
 * | `url`              | `String`  | The fully-built authorization URI to open in a Custom Tabs session.    |
 * | `ephemeralSession` | `Boolean` | When `true`, passes `setEphemeralBrowsingEnabled(true)` to             |
 * |                    |           | [CustomTabsIntent.Builder], opening the session in private/incognito   |
 * |                    |           | mode and preventing reuse of existing cookies. Defaults to `false`.    |
 * |                    |           | Note: this is a Chrome-specific API; other providers may ignore it.    |
 *
 * ## Result
 * - **`RESULT_OK`** — authorization succeeded; the `code` string extra contains the authorization
 *   code to exchange for tokens via [OAuthProvider.authorize].
 * - **`RESULT_CANCELED`** — the user dismissed the browser session or the redirect did not carry
 *   a `code` parameter.
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