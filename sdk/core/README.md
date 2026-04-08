# IBM Verify Core SDK for Android

**Version:** 3.2.0
**Package:** `com.ibm.security.verifysdk.core`

The IBM Verify Core SDK for Android provides common functionality and utilities used across all other SDK modules. It includes networking helpers, keystore management, logging extensions, and base exception classes.

## Key Components

### NetworkHelper
Singleton providing HTTP client configuration with optional Certificate Transparency verification.

```kotlin
// Basic usage
val client = NetworkHelper.getInstance

// With Certificate Transparency (recommended for production)
NetworkHelper.certificateTransparencyInterceptor = certificateTransparencyInterceptor {
    // Configure CT verification
}
```

### KeystoreHelper
Secure key management using the Android Keystore system.

```kotlin
// Generate key pair
val keyPair = KeystoreHelper.generateKeyPair(
    alias = "my-key",
    requireUserAuthentication = true
)

// Sign data
val signature = KeystoreHelper.sign(alias = "my-key", data = dataToSign)
```

### Exception Classes
- `VerifySdkException`: Base exception for all SDK errors
- `AuthenticationException`: Authentication-specific errors with detailed error codes

## Recent Improvements (v3.2.0)

- **Certificate Transparency Support**: Optional CT verification via interceptor method (SDK best practice)
- **Thread-Safe Networking**: Improved HttpClient initialization and lifecycle management
- **Performance Optimizations**: Lazy logging to prevent string allocation when logging disabled
- **Platform Independence**: Explicit StandardCharsets.UTF_8 usage for consistent behavior across platforms
- **Improved Test Coverage**: Comprehensive test cases for KeystoreHelper and core utilities
- **Better Error Handling**: Structured exception hierarchy with error chaining

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

See `docs/CERTIFICATE_TRANSPARENCY_GUIDE.md` for detailed setup instructions.

## Dependencies

The Core SDK is a dependency for all other SDK modules:
- `:sdk:authentication`
- `:sdk:mfa`
- `:sdk:fido2`
- `:sdk:adaptive`

## Requirements

- **Minimum SDK**: API 29 (Android 10.0)
- **Target SDK**: API 36 (Android 16)
- **Kotlin**: 2.1.0+
- **Ktor**: 3.0.3+

## License

This SDK is licensed under the Apache License 2.0. See the LICENSE file for details.