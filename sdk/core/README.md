# IBM Verify Core SDK for Android

![SDK Version](https://img.shields.io/github/v/release/ibm-verify/verify-sdk-android?label=IBM%20Security%20Verify%20Core%20SDK)
![Android Version](https://img.shields.io/badge/Android-10+-green.svg)
![Android Version](https://img.shields.io/badge/Android%20API-29+-green.svg)

**Package:** `com.ibm.security.verifysdk.core`

The IBM Verify Core SDK for Android provides common functionality and utilities used across all other SDK modules. It includes networking helpers, keystore management, logging extensions, and base exception classes.

## Key Components

### NetworkHelper
Singleton providing HTTP client configuration with optional Certificate Transparency verification and SSL bypass support for on-premise deployments.

```kotlin
// Basic usage
val client = NetworkHelper.getInstance

// With Certificate Transparency (recommended for production)
NetworkHelper.certificateTransparencyInterceptor = certificateTransparencyInterceptor {
    // Configure CT verification
}

// Enable SSL bypass for on-premise servers with self-signed certificates
// WARNING: Only enable if you trust the servers
NetworkHelper.allowInsecureSSL = true
val insecureClient = NetworkHelper.createInsecureClient()
```

### KeystoreHelper
Secure key management using the Android Keystore system.

```kotlin
// Generate a key pair in the Android Keystore and get the public key
val publicKey = KeystoreHelper.createKeyPair(
    keyName = "my-key",
    algorithm = "SHA256withRSA",
    purpose = KeyProperties.PURPOSE_SIGN,
    authenticationRequired = false
)

// Sign data (returns the Base64-encoded signature for String input)
val signature = KeystoreHelper.signData(
    keyName = "my-key",
    algorithm = "SHA256withRSA",
    dataToSign = "data to sign"
)
```

### Exception Classes
- `VerifySdkException`: Base exception for all SDK errors
- `AuthenticationException`: Authentication-specific errors with detailed error codes

## Recent Improvements (v3.2.12)

- **Dependency updates**: Jackson 2.22.3. No Core SDK production code changed in this release.

### (v3.2.11)

- **Netty Security Update**: `io.netty:netty-codec-http2`, `netty-codec-compression`, and `netty-handler-proxy` force-pinned to `4.2.17.Final` (from `4.2.15.Final`).

### (v3.2.10)

- **`KeystoreHelper.createKeyPair` extended**: Three new optional parameters — `userAuthenticationTimeout: Int` (seconds key remains authorised after auth; `0` = per-use), `userAuthenticationTypes: Int` (authenticator bitmask; default `AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL`), and `unlockedDeviceRequired: Boolean` (`setUnlockedDeviceRequired`; API 28+). All three are backward-compatible.
- **Jackson `force()` scope fix**: Jackson version constraints are now enforced across every Gradle configuration (not just Dokka), ensuring `jackson-databind:2.22.1` is never resolved transitively.
- **New `KeystoreHelper` tests**: 7 new tests covering all combinations of the new `createKeyPair` parameters across RSA and EC key types.
- **SSL Certificate Bypass Support**: Two-level security model for on-premise authenticators with self-signed certificates.
- **Certificate Transparency Support**: Optional CT verification via interceptor method (SDK best practice).

## Certificate Transparency

The Core SDK supports optional Certificate Transparency verification using the interceptor method (recommended for SDK implementations):

```kotlin
import com.appmattus.certificatetransparency.certificateTransparencyInterceptor

// Configure CT verification
NetworkHelper.certificateTransparencyInterceptor = certificateTransparencyInterceptor {
    // Fail on CT errors (recommended for production)
    failOnError = true
    
    // Optional: Add trusted CT logs
    // +LogListDataSourceFactory.logListService
}

// Use NetworkHelper as normal
val client = NetworkHelper.getInstance
```

**Benefits:**
- Scoped to SDK only (won't conflict with client app's CT configuration)
- No Security Provider conflicts
- Easy to configure and test
- Optional (disabled by default for backward compatibility)

## SSL Certificate Bypass (On-Premise Only)

For on-premise deployments with self-signed certificates, the Core SDK provides a controlled SSL bypass mechanism:

```kotlin
// Enable SSL bypass capability (app-level permission)
NetworkHelper.allowInsecureSSL = true

// Create insecure client for specific authenticators
val insecureClient = NetworkHelper.createInsecureClient()
```

**Two-Level Security Model:**
1. **App-Level Permission**: `NetworkHelper.allowInsecureSSL` must be explicitly enabled
2. **Authenticator-Level Need**: QR code must include `"options":"ignoreSslCerts=true"`

**Security Warning:** ⚠️ Only enable SSL bypass for trusted on-premise servers. This exposes your application to man-in-the-middle attacks.

**Default Behavior:**
- SSL bypass is disabled by default (`allowInsecureSSL = false`)
- Attempting to create insecure client when disabled throws `IllegalStateException`
- All authenticators use standard SSL certificate validation by default

See [`docs/SSL_CERTIFICATE_BYPASS.md`](../../docs/SSL_CERTIFICATE_BYPASS.md) for the full security model, and [`docs/releases/3.2.8.md`](../../docs/releases/3.2.8.md) for the release that introduced it.

## Dependencies

The Core SDK is a dependency for all other SDK modules:
- `:sdk:authentication`
- `:sdk:mfa`
- `:sdk:fido2`
- `:sdk:adaptive`

## Requirements

- **Minimum SDK**: API 29 (Android 10.0)
- **Target SDK**: API 36 (Android 16)
- **Kotlin**: 2.3+
- **Ktor**: 3.4+

## License

This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.