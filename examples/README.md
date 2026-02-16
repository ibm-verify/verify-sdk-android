# IBM Verify SDK - Example Applications

This directory contains demonstration Android applications showcasing various capabilities of the IBM Verify SDK. Each example app is a standalone project that demonstrates specific SDK features and best practices.

## Available Examples

### 1. MFA Demo (`mfa_demo/`)

Demonstrates the MFA (Multi-Factor Authentication) capabilities of the IBM Verify SDK.

**Features:**

- QR code-based authenticator registration
- Transaction verification and approval/denial
- Biometric authentication (Face ID/Fingerprint)
- Support for Cloud and On-Premise authenticators
- Modern Material Design 3 UI with Jetpack Compose

**Documentation:** [mfa_demo/README.md](mfa_demo/README.md)

---

### 2. DPoP Demo (`dpop_demo/`)

Demonstrates configuring DPoP (Demonstrating Proof-of-Possession) flows with IBM Verify.

**Features:**

- DPoP token generation
- Proof-of-possession authentication
- Secure token binding
- Network request signing

**Documentation:** [dpop_demo/README.md](dpop_demo/README.md)

**Additional Resources:** Supporting assets for articles published on [IBM Verify Docs](https://docs.verify.ibm.com/verify)

---

### 3. FIDO2 Demo (`fido2_demo/`)

Demonstrates FIDO2 (WebAuthn) authentication capabilities using the IBM Verify SDK.

**Features:**
- FIDO2 registration
- FIDO2 authentication
- Passwordless authentication
- Biometric authentication support

**SDK Module:** `sdk:fido2`

---

### 4. AuthCodeFlow Demo (`authcodeflow_demo/`)

Demonstrates OAuth 2.0 Authorization Code Flow with PKCE and OIDC using the IBM Verify SDK.

**Features:**

- OAuth 2.0 Authorization Code Flow
- PKCE (Proof Key for Code Exchange) support
- Browser-based authentication via system browser
- Android App Links for OAuth redirect handling
- Token exchange

**Documentation:** [authcodeflow_demo/README.md](authcodeflow_demo/README.md)

**SDK Module:** `sdk:authentication`
