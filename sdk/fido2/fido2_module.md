# Module IBM Verify FIDO2(TM) SDK for Android

The IBM Verify FIDO2™ SDK for Android is a native implementation of FIDO attestation and
assertion ceremonies. The SDK essentially provides the equivalent of
WebAuthn's `navigator.credentials.create()` and `navigator.credentials.get()` for native mobile
applications with specific security requirements. It is distinctly different from
Google's [FIDO2 API for Android](https://developers.google.com/identity/fido/android/native-apps),
in the following ways:

- The Verify FIDO2 SDK for Android always creates device-bound ES256 keys using the Android
  native [KeyPairGenerator API](https://developer.android.com/reference/kotlin/java/security/KeyPairGenerator.html).
  The Verify FIDO2 SDK for Android integrates with platform credential management and permits
  credential creation including synchronised credentials in any registered credential provider.
- The Verify FIDO2 SDK for Android allows the integration of extensions such as the `txAuthSimple`
  extension which facilitates "what you see is what you sign" operations. The FIDO2 API for Android
  is for authentication only and does not support modifications to the text displayed in system
  authentication dialogs.
- The Verify FIDO2 SDK for Android permits integration of your own attestation implementation if
  desired. The FIDO2 API for Android currently relies on Google Play Store to provide an
  attestation. This is not always available on all Android devices.

This Verify FIDO2 SDK for Android is well suited for developers of pure native mobile applications
that wish to provision only device-bound keys in scenarios where the use of synchronized passkeys
for example is not suitable.

## Example

An [example](https://github.com/ibm-verify/verify-sdk-android/tree/main/examples/fido2_demo)
application is available for the Verify FIDO2 SDK for Android.

## Usage

For convenience, the SDK provides a network request handler. Alternatively, you can use your own
handler and use the SDK to create and parse the data.

### Attestation

#### Initiate attestation

To get the attestation options, perform a HTTPS request to a relying party
endpoint  `POST <server>/attestation/options`. The call needs to be executed in a coroutine.

```Kotlin
val fido2Api = Fido2Api()

lifecycleScope.launch {
    fido2Api.initiateAttestation(
        attestationOptionsUrl = "$relyingPartyUrl/attestation/options",
        authorization = accessToken,
        AttestationOptions(displayName = "Thomas J. Watson")
    )
        .onSuccess { publicKeyCredentialCreationOptions ->
            println("Success: $publicKeyCredentialCreationOptions")
            // handle PublicKeyCredentialCreationOptions
        }
        .onFailure {
            println("Failure: $it.message")
        }
}
```

#### Send attestation request

Create an attestation request using the `PublicKeyCredentialCreationOptions` from the previous
section.

```Kotlin
// Construct builder for the biometric authentication dialog
val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
    .setTitle("FIDO2 Demo")
    .setSubtitle("User Verification")
    .setNegativeButtonText("Cancel")

// Define flags for Attestation Credential Data
var flags: Byte = 0x01  // userPresence (UP)
flags = (flags or 0x04) // userVerification (UV)
flags = (flags or 0x40) // attestedCredentialData (AT)
```

Pass the activity context, the dialog builder, the `publicKeyCredentialCreationOptions` from the
previous network request and other parameters to generate the `AuthenticatorAttestationResponse`.
Due to the authentication dialog, this call needs to be wrapped in a coroutine.

```Kotlin
lifecycleScope.launch {
    val authenticatorAssertionResponse: AuthenticatorAttestationResponse =
        fido2Api.buildAuthenticatorAttestationResponse(
            this@RegistrationActivity,
            ContextCompat.getMainExecutor(this@RegistrationActivity),
            promptInfoBuilder,
            "ABCDEFGH-1234-5678-IJKL-MNOPQRSTUVWX",
            keyName,
            flags,
            publicKeyCredentialCreationOptions,
            nickName
        )
}
```

Send the `AuthenticatorAttestationResponse` to the `POST <server>/attestation/result` endpoint:

```Kotlin
fido2Api.sendAttestation(
    attestationResultUrl = "$relyingPartyUrl/attestation/result",
    authorization = accessToken,
    authenticatorAssertionResponse
)
    .onSuccess { attestationResultResponse ->
        println("Success: $attestationResultResponse")
        // handle AttestationResultResponse
    }
    .onFailure {
        println("Failure: $it.message")
    }
```

### Assertion

#### Initiate assertion

To get assertion options, perform a HTTPS request to a relying party
endpoint `POST <server>/assertion/options` with `userVerification = preferred`.

```Kotlin
lifecycleScope.launch {
    fido2Api.initiateAssertion(
        assertionOptionsUrl = "$relyingPartyUrl/assertion/options",
        authorization = accessToken,
        AssertionOptions(userName, "preferred")
    )
        .onSuccess { publicKeyCredentialRequestOptions ->
            println("Success: $publicKeyCredentialRequestOptions")
            // handle PublicKeyCredentialRequestOptions
        }

        .onFailure {
            println("Failure: $it.message")
        }
}
```

#### Send assertion request

Create an `AuthenticatorAssertionResponse` using the `PublicKeyCredentialRequestOptions` from the
previous section.

```Kotlin
// Construct builder for the biometric authentication dialog
val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
    .setTitle("FIDO2 Demo")
    .setSubtitle(transactionMessage)
    .setNegativeButtonText("Cancel")

// Define flags for Attestation Credential Data
var flags: Byte
val message: String?

// Add transaction message if enabled
if (allowTransaction) {
    flags = 0x01.toByte()               // userPresence (UP)
    flags = (flags or 0x04)             // userVerification (UV)
    flags = (flags or 0x80.toByte())    // extensionData (ED)
    message = transactionMessage
} else {
    flags = 0x01            // userPresence (UP)
    flags = (flags or 0x04) // userVerification (UV)
    message = null
}
```

Pass the activity context, the dialog builder, the `publicKeyCredentialRequestOptions` from the
previous network request and other parameters to generate the `AuthenticatorAssertionResponse`. Due
to the authentication dialog, this call needs to be wrapped in a coroutine.

```Kotlin
lifecycleScope.launch {
    val authenticatorAssertionResponse: AuthenticatorAssertionResponse =
        fido2Api.buildAuthenticatorAssertionResponse(
            this@AuthenticationActivity,
            ContextCompat.getMainExecutor(this@AuthenticationActivity),
            promptInfoBuilder,
            keyName,
            flags,
            publicKeyCredentialRequestOptions,
            message
        )
}
```

Send the `authenticatorAssertionResponse` to the `POST <server>/assertion/result` endpoint:

```Kotlin
lifecycleScope.launch {
    fido2Api.sendAssertion(
        assertionResultUrl = "$relyingPartyUrl/assertion/result",
        authorization = accessToken,
        authenticatorAssertionResponse
    )
        .onSuccess { assertionResultResponse ->
            println("Success: $assertionResultResponse")
            // handle AssertionResultResponse
        }

        .onFailure {
            println("Failure: ${it.message}")
        }
}
```

### License

FIDO™ and FIDO2™ are trademarks (registered in numerous countries) of FIDO Alliance, Inc.

# Package com.ibm.security.verifysdk.fido2
