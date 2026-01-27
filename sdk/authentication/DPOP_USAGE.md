# DPoP (Demonstrating Proof-of-Possession) Support

## Overview

The IBM Verify Authentication SDK now supports DPoP (Demonstrating Proof-of-Possession) for OAuth 2.0, as defined in [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449). DPoP is a mechanism for sender-constraining OAuth 2.0 tokens via a proof-of-possession mechanism at the application layer.

## Features

- Automatic generation of DPoP proof tokens using RSA keys stored in Android KeyStore
- Support for DPoP in authorization code flow
- Support for DPoP in password grant flow
- Support for DPoP in token refresh operations
- Automatic inclusion of access token hash (ath) claim when applicable

## Usage

### Enabling DPoP

To enable DPoP support in your OAuth provider, simply set the `useDPoP` property to `true`:

```kotlin
val oauthProvider = OAuthProvider(
    clientId = "your-client-id",
    clientSecret = "your-client-secret"
)

// Enable DPoP
oauthProvider.useDPoP = true
```

### Using a Custom Key Alias

By default, DPoP uses a predefined key alias for storing the RSA key pair in the Android KeyStore. You can specify a custom key alias if needed:

```kotlin
val oauthProvider = OAuthProvider(
    clientId = "your-client-id",
    clientSecret = "your-client-secret"
)

// Enable DPoP with custom key alias
oauthProvider.useDPoP = true
oauthProvider.dpopKeyAlias = "my-custom-dpop-key"
```

This is useful when:
- You want to use different keys for different OAuth providers
- You need to manage multiple DPoP key pairs in your application
- You want to implement key rotation strategies

### Authorization Code Flow with DPoP

```kotlin
// Enable DPoP
oauthProvider.useDPoP = true

// Perform authorization - DPoP header will be automatically included
val result = oauthProvider.authorize(
    url = tokenEndpointUrl,
    redirectUrl = redirectUrl,
    authorizationCode = code,
    codeVerifier = codeVerifier
)

result.onSuccess { tokenInfo ->
    println("Access token: ${tokenInfo.accessToken}")
    println("Token type: ${tokenInfo.tokenType}") // Should be "DPoP"
}
```

### Password Grant Flow with DPoP

```kotlin
// Enable DPoP
oauthProvider.useDPoP = true

// Perform authorization with username/password
val result = oauthProvider.authorize(
    url = tokenEndpointUrl,
    username = "user@example.com",
    password = "password123"
)

result.onSuccess { tokenInfo ->
    println("Access token: ${tokenInfo.accessToken}")
}
```

### Token Refresh with DPoP

```kotlin
// Enable DPoP
oauthProvider.useDPoP = true

// Refresh token - DPoP header will be automatically included
val result = oauthProvider.refresh(
    url = tokenEndpointUrl,
    refreshToken = tokenInfo.refreshToken
)

result.onSuccess { newTokenInfo ->
    println("New access token: ${newTokenInfo.accessToken}")
}
```

### Using DPoP Tokens with Resource Servers

When making requests to resource servers that require DPoP, you need to include both the access token and a DPoP proof token:

```kotlin
import com.ibm.security.verifysdk.authentication.DPoPHelper

// Generate DPoP proof token for the resource server request
val dpopProof = DPoPHelper.generateDPoPToken(
    htu = "https://resource.example.com/api/data",
    htm = "GET",
    accessToken = tokenInfo.accessToken
)

// Make the request with both headers
val response = httpClient.get("https://resource.example.com/api/data") {
    header("Authorization", "DPoP ${tokenInfo.accessToken}")
    header("DPoP", dpopProof)
}
```

## DPoP Helper Methods

The `DPoPHelper` class provides utility methods for working with DPoP:

### Generate DPoP Token

```kotlin
// Using default key alias
val dpopToken = DPoPHelper.generateDPoPToken(
    htu = "https://example.com/token",
    htm = "POST",
    accessToken = null // or provide access token for ath claim
)

// Using custom key alias
val dpopToken = DPoPHelper.generateDPoPToken(
    htu = "https://example.com/token",
    htm = "POST",
    accessToken = tokenInfo.accessToken,
    keyAlias = "my-custom-dpop-key"
)
```

### Check if Key Exists

```kotlin
// Check default key
val hasKey = DPoPHelper.hasKey()

// Check custom key
val hasCustomKey = DPoPHelper.hasKey("my-custom-dpop-key")
```

### Delete DPoP Key

```kotlin
// Delete default key
DPoPHelper.deleteKey()

// Delete custom key
DPoPHelper.deleteKey("my-custom-dpop-key")
```

## Key Management

- DPoP keys are automatically generated and stored in the Android KeyStore
- Keys are 2048-bit RSA keys with SHA-256 signing
- Keys persist across app sessions
- Keys are hardware-backed when available on the device

## Security Considerations

1. **Key Storage**: DPoP keys are stored in the Android KeyStore, which provides hardware-backed security on supported devices.

2. **Token Binding**: DPoP tokens are cryptographically bound to the client's key pair, preventing token theft and replay attacks.

3. **Access Token Hash**: When making requests to resource servers, the DPoP proof includes a hash of the access token (ath claim) to bind the proof to the specific token.

4. **Replay Protection**: Each DPoP proof includes a unique JWT ID (jti) and timestamp (iat) to prevent replay attacks.

## Requirements

- Android API Level 23 (Marshmallow) or higher
- IBM Verify SDK for Android 3.1.0 or higher
- OAuth 2.0 authorization server with DPoP support

## Example

See the `dpop_demo` example app for a complete implementation of DPoP with the IBM Verify SDK.

## Troubleshooting

### DPoP Token Generation Fails

If DPoP token generation fails, check:
- Device supports Android KeyStore (API 23+)
- App has necessary permissions
- KeyStore is not corrupted

### Authorization Server Rejects DPoP Token

If the authorization server rejects the DPoP token:
- Verify the server supports DPoP
- Check that the `htu` claim matches the token endpoint URL exactly
- Ensure the `htm` claim matches the HTTP method ("POST" for token requests)
- Verify the server's DPoP configuration (key algorithms, required claims, etc.)

## References

- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [Android KeyStore System](https://developer.android.com/training/articles/keystore)