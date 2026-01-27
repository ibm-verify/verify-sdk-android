# IBM Verify SDK for Android

This directory contains the core SDK modules for IBM Verify on Android. Each module provides specific functionality for authentication, security, and identity management.

## SDK Modules

### [Core](core/)
The IBM Verify Core SDK provides common functionality across all other SDK modules including:
- Keychain and secure storage utilities
- HTTP networking with Ktor
- Shared data models and utilities
- Biometric authentication support

**Dependencies**: None (base module)

---

### [Authentication](authentication/)
The IBM Verify Authentication SDK implements OAuth 2.0 and OpenID Connect (OIDC) protocols for mobile applications.

**Key Features**:
- OAuth 2.0 Authorization Code Flow with PKCE
- Password Grant Flow
- Token refresh and management
- DPoP (Demonstrating Proof-of-Possession) support
- OIDC Discovery
- Browser-based authentication with Android App Links

**Dependencies**: `core`

**Documentation**: [Authentication README](authentication/README.md) | [DPoP Usage Guide](authentication/DPOP_USAGE.md)

**Example**: [Authorization Code Flow Demo](../examples/authcodeflow_demo/)

---

### [MFA](mfa/)
The IBM Verify MFA SDK provides multi-factor authentication capabilities for mobile applications.

**Key Features**:
- TOTP (Time-based One-Time Password) generation
- HOTP (HMAC-based One-Time Password) support
- Biometric authentication (Face ID, Fingerprint)
- User presence verification
- Transaction signing
- Push notification authentication
- Cloud and On-Premise support

**Dependencies**: `core`, `authentication`

**Documentation**: API docs available at [ibm-verify.github.io/android/mfa/docs](https://ibm-verify.github.io/android/mfa/docs/)

**Example**: [MFA Demo](../examples/mfa_demo/)

---

### [FIDO2](fido2/)
The IBM Verify FIDO2™ SDK is a native implementation of FIDO attestation and assertion ceremonies for Android.

**Key Features**:
- Device-bound ES256 key generation
- WebAuthn-equivalent operations for native apps
- Biometric authentication integration
- Transaction authorization with `txAuthSimple` extension
- Custom attestation support
- No dependency on Google Play Services

**Dependencies**: `core`

**Documentation**: [FIDO2 README](fido2/README.md)

**Example**: [FIDO2 Demo](../examples/fido2_demo/)

---

### [Adaptive](adaptive/)
The IBM Verify Adaptive SDK provides device risk assessment and adaptive authentication capabilities.

**Key Features**:
- Device fingerprinting and assessment
- Trusteer SDK integration
- Risk-based authentication policies
- Factor generation (Email OTP, SMS OTP)
- Factor evaluation (Password, OTP)
- Session management

**Dependencies**: `core`

**Documentation**: [Adaptive README](adaptive/README.md)

**Requirements**: 
- Trusteer SDK (obtained via IBM Verify admin portal)
- Adaptive Proxy SDK on server side

---

### [DC (Digital Credentials)](dc/)
The IBM Verify Digital Credentials SDK enables credential issuance and verification in mobile wallet applications.

**Key Features**:
- Wallet initialization and management
- Credential issuance and acceptance
- Proof request handling
- Verification workflows
- Support for multiple credential formats (Indy, JSON-LD, mDoc)
- Connection management with issuers and verifiers

**Dependencies**: `core`

**Documentation**: [DC README](dc/README.md)

**Example**: [DC Demo](../examples/dc_demo/)

---

## Module Dependency Graph

```
┌─────────────────────────────────────────────────────────┐
│                         Core                            │
│  (Networking, Storage, Biometrics, Common Utilities)    │
└─────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┬─────────┐
        │                   │                   │         │
        ▼                   ▼                   ▼         ▼
┌──────────────┐    ┌──────────────┐    ┌──────────┐  ┌────────┐
│Authentication│    │    FIDO2     │    │ Adaptive │  │   DC   │
└──────────────┘    └──────────────┘    └──────────┘  └────────┘
        │
        ▼
┌──────────────┐
│     MFA      │
└──────────────┘
```

## Integration

To use any SDK module in your Android project, add the dependency to your `build.gradle.kts`:

```kotlin
dependencies {
    // Core module (required for all other modules)
    implementation("com.github.ibm-verify.verify-sdk-android:verify-sdk-core:3.0.9")
    
    // Add specific modules as needed
    implementation("com.github.ibm-verify.verify-sdk-android:verify-sdk-authentication:3.0.9")
    implementation("com.github.ibm-verify.verify-sdk-android:verify-sdk-mfa:3.0.9")
    implementation("com.github.ibm-verify.verify-sdk-android:verify-sdk-fido2:3.0.9")
    implementation("com.github.ibm-verify.verify-sdk-android:verify-sdk-adaptive:3.0.9")
    implementation("com.github.ibm-verify.verify-sdk-android:verify-sdk-dc:3.0.9")
}
```

See the [main README](../README.md#integrating-with-your-project) for complete integration instructions.

## API Documentation

API documentation for each module is available at:
- [Core API Docs](https://ibm-verify.github.io/android/core/docs/)
- [Authentication API Docs](https://ibm-verify.github.io/android/authentication/docs/)
- [MFA API Docs](https://ibm-verify.github.io/android/mfa/docs/)
- [FIDO2 API Docs](https://ibm-verify.github.io/android/fido2/docs/)
- [Adaptive API Docs](https://ibm-verify.github.io/android/adaptive/docs/)
- [DC API Docs](https://ibm-verify.github.io/android/dc/docs/)

## Examples

Complete example applications demonstrating each SDK module are available in the [examples](../examples/) directory:

- [Authorization Code Flow Demo](../examples/authcodeflow_demo/) - OAuth 2.0 with PKCE
- [MFA Demo](../examples/mfa_demo/) - Multi-factor authentication
- [FIDO2 Demo](../examples/fido2_demo/) - FIDO2 attestation and assertion
- [DC Demo](../examples/dc_demo/) - Digital credentials wallet

## Requirements

- **Minimum Android API Level**: 23 (Android 6.0 Marshmallow)
- **Target Android API Level**: 31+
- **Kotlin Version**: 1.9+
- **Build System**: Gradle with Kotlin DSL

## Common Dependencies

All SDK modules share these common dependencies:
- AndroidX Core KTX
- AndroidX AppCompat
- Ktor (HTTP client)
- kotlinx-serialization (JSON handling)
- kotlinx-coroutines (Async operations)

## Support

For issues, questions, or contributions:
- **Issues**: [GitHub Issues](https://github.com/ibm-verify/verify-sdk-android/issues)
- **Documentation**: [IBM Verify Documentation](https://docs.verify.ibm.com/)
- **Contributing**: See [CONTRIBUTING.md](../CONTRIBUTING.md)

## License

This package contains code licensed under the MIT License. See [LICENSE](../LICENSE) for details.