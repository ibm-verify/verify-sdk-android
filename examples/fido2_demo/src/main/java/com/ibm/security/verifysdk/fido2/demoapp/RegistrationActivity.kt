/*
 *  Copyright contributors to the IBM Verify FIDO2 Sample App for Android project
 */
package com.ibm.security.verifysdk.fido2.demoapp

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import com.google.android.material.textfield.TextInputEditText
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.ibm.security.verifysdk.core.AuthorizationException
import com.ibm.security.verifysdk.core.ErrorMessage
import com.ibm.security.verifysdk.core.helper.NetworkHelper
import com.ibm.security.verifysdk.core.serializer.DefaultJson
import com.ibm.security.verifysdk.fido2.api.Fido2Api
import com.ibm.security.verifysdk.fido2.demoapp.model.IvCreds
import com.ibm.security.verifysdk.fido2.model.AttestationOptions
import com.ibm.security.verifysdk.fido2.model.AuthenticatorAttestationResponse
import com.ibm.security.verifysdk.fido2.model.PublicKeyCredentialCreationOptions
import io.ktor.client.call.body
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.get
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.launch
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import java.time.LocalDateTime
import kotlin.experimental.or

class RegistrationActivity : AppCompatActivity() {

    private val fido2Api = Fido2Api()
    private val keyName = "61683285-900f-4bed-87e0-b83b5277ba93"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_registration)

        // Set version info in toolbar
        val versionName = packageManager.getPackageInfo(packageName, 0).versionName
        val versionCode = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            packageManager.getPackageInfo(packageName, 0).longVersionCode.toInt()
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, 0).versionCode
        }
        
        val versionTextView: TextView = findViewById(R.id.text_view_version)
        versionTextView.text = "$versionName ($versionCode)"

        findViewById<Button>(R.id.button_initiate_registration).setOnClickListener {

            findViewById<TextInputEditText>(R.id.edit_text_access_token).let { editText ->
                if (editText.text.toString().isNotEmpty()) {
                    getSharedPreferences(application.packageName, Context.MODE_PRIVATE).edit().putString(
                        "accessToken", editText.text.toString()
                    ).apply()
                }
            }

            val relyingPartyUrl =
                findViewById<TextInputEditText>(R.id.edit_text_relying_party_url).text.toString()
            val nickName =
                findViewById<TextInputEditText>(R.id.edit_text_nickname).text.toString()
            val accessToken = getSharedPreferences(
                application.packageName,
                Context.MODE_PRIVATE
            ).getString("accessToken", null) ?: ""

            lifecycleScope.launch {
                getWhoAmI(accessToken)
                    .onSuccess { ivCreds ->
                        if (ivCreds.AZN_CRED_PRINCIPAL_NAME.isNotEmpty()) {

                            getSharedPreferences(
                                application.packageName,
                                Context.MODE_PRIVATE
                            )
                                .edit()
                                .putString("accessToken", accessToken)
                                .putString("nickName", nickName)
                                .putString("displayName", ivCreds.name)
                                .putString("userName", ivCreds.username)
                                .putString("email", ivCreds.email)
                                .apply()

                            fido2Api.initiateAttestation(
                                attestationOptionsUrl = "$relyingPartyUrl/attestation/options",
                                authorization = accessToken,
                                AttestationOptions(displayName = ivCreds.name)
                            )
                                .onSuccess { publicKeyCredentialCreationOptions ->
                                    sendAttestationOptionsResult(
                                        publicKeyCredentialCreationOptions,
                                        relyingPartyUrl,
                                        accessToken,
                                        nickName.ifEmpty { "FIDO2App - Android" }
                                    )
                                }
                                .onFailure {
                                    println("Failure: $it.message")
                                }
                        }
                    }
                    .onFailure {
                        println("Failure: $it.message")
                        displayError("${it.message}")
                    }
            }
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    private suspend fun getWhoAmI(
        accessToken: String
    ): Result<IvCreds> {

        return try {
            val response = NetworkHelper.getInstance.get {
                url("https://fidointerop.securitypoc.com/ivcreds")
                bearerAuth(accessToken)
                contentType(ContentType.Application.Json)
            }

            if (response.status.isSuccess()) {
                Result.success(DefaultJson.decodeFromString<IvCreds>(response.bodyAsText()))
           } else {
                val errorResponse = response.body<ErrorMessage>()
                Result.failure(
                    AuthorizationException(
                        response.status,
                        errorResponse.error,
                        errorResponse.errorDescription
                    )
                )
            }
        } catch (e: Throwable) {
            Result.failure(e)
        }
    }

    private fun sendAttestationOptionsResult(
        publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
        rpUrl: String, accessToken: String, nickName: String
    ) {

        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle("FIDO2 Demo")
            .setSubtitle("User Verification")
            .setNegativeButtonText("Cancel")

        var flags: Byte = 0x01 // userPresence (UP)
        flags = (flags or 0x04)  // userVerification (UV)
        flags = (flags or 0x40)  // attestedCredentialData (AT)

        lifecycleScope.launch {

            val authenticatorAssertionResponse: AuthenticatorAttestationResponse =
                fido2Api.buildAuthenticatorAttestationResponse(
                    this@RegistrationActivity,
                    ContextCompat.getMainExecutor(this@RegistrationActivity),
                    promptInfoBuilder,
                    "6DC9F22D-2C0A-4461-B878-DE61E159EC61",
                    keyName,
                    flags,
                    publicKeyCredentialCreationOptions,
                    nickName
                )

            fido2Api.sendAttestation(
                attestationResultUrl = "$rpUrl/attestation/result",
                authorization = accessToken,
                authenticatorAssertionResponse
            )
                .onSuccess {
                    val sharedPreferences =
                        getSharedPreferences(application.packageName, Context.MODE_PRIVATE)
                    with(sharedPreferences.edit()) {
                        putString("accessToken", accessToken)
                        putString("relyingPartyUrl", rpUrl)
                        putString("nickName", nickName)
                        putString("createdAt", LocalDateTime.now().toString())
                        apply()
                    }
                    startActivity(
                        Intent(
                            this@RegistrationActivity,
                            AuthenticationActivity::class.java
                        )
                    )
                }
                .onFailure {
                    displayError("${it.message}")
                }
        }
    }

    private fun displayError(error: String) {
        runOnUiThread {
            val errorDialogBuilder = AlertDialog.Builder(
                this@RegistrationActivity
            )
            errorDialogBuilder.setTitle("Failure")
            errorDialogBuilder.setMessage(error)
            errorDialogBuilder.setCancelable(false)
            errorDialogBuilder.setPositiveButton("Ok", null)

            val errorDialog = errorDialogBuilder.create()
            errorDialog.show()

            val mPositiveButton = errorDialog.getButton(AlertDialog.BUTTON_POSITIVE)
            mPositiveButton.setOnClickListener {
                errorDialog.cancel()
            }
        }
    }
}