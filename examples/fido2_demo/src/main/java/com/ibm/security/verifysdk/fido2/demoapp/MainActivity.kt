/*
 *  Copyright contributors to the IBM Verify FIDO2 Sample App for Android project
 */
package com.ibm.security.verifysdk.fido2.demoapp

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.ibm.security.verifysdk.core.helper.KeystoreHelper
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.fido2.api.Fido2Api
import okhttp3.logging.HttpLoggingInterceptor


class MainActivity : AppCompatActivity() {

    private val keyName = "61683285-900f-4bed-87e0-b83b5277ba93"
    private val fido2Api = Fido2Api()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Set version info in toolbar
        val versionName = packageManager.getPackageInfo(packageName, 0).versionName
        val versionCode =
            packageManager.getPackageInfo(packageName, 0).longVersionCode.toInt()

        val versionTextView: TextView = findViewById(R.id.text_view_version)
        versionTextView.text = "$versionName ($versionCode)"
        
        NetworkHelper.customLoggingInterceptor =
            HttpLoggingInterceptor().setLevel(HttpLoggingInterceptor.Level.BODY)

        if (KeystoreHelper.exists(keyName).not()) {
            fido2Api.createKeyPair(
                keyName = keyName,
                authenticationRequired = true,
                invalidatedByBiometricEnrollment = false
            )
        }

        findViewById<Button>(R.id.button_get_started_isva).setOnClickListener {
            startActivity(Intent(this, RegistrationActivity::class.java))
        }

        NetworkHelper.initialize()
        redirectToAuthenticationIfLoggedIn()
    }

    private fun redirectToAuthenticationIfLoggedIn() {
        val sharedPreferences =
            getSharedPreferences(application.packageName, Context.MODE_PRIVATE)

        val accessToken = sharedPreferences.getString("accessToken", "") ?: ""
        if (accessToken.isNotEmpty()) {
            startActivity(Intent(this, AuthenticationActivity::class.java))
        }
    }
}