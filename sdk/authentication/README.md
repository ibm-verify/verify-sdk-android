# IBM Verify Authentication SDK for Android

![SDK Version](https://img.shields.io/badge/IBM%20Security%20Verify%20Authentication%20SDK-3.0.0-blue.svg)
![Android Version](https://img.shields.io/badge/Android-12-green.svg)
![Android Version](https://img.shields.io/badge/Android%20API-31-green.svg)

The IBM Verify Authentication SDK for Android is a comprehensive implementation of OAuth 2.0 and OpenID Connect (OIDC) protocols, specifically designed for native mobile applications. It provides secure authentication flows with support for modern security standards including PKCE and DPoP.

## Features

- **OAuth 2.0 Authorization Code Flow** - Standard OAuth 2.0 authorization with browser-based authentication
- **PKCE Support** - Proof Key for Code Exchange for enhanced security in public clients
- **DPoP Support** - Demonstrating Proof-of-Possession for sender-constrained tokens (RFC 9449)
- **OpenID Connect** - Full OIDC support including ID tokens and userinfo endpoints
- **Password Grant Flow** - Resource Owner Password Credentials grant type
- **Token Refresh** - Automatic token refresh with refresh tokens
- **OIDC Discovery** - Automatic endpoint discovery via `.well-known/openid-configuration`
- **Browser-based Authentication** - Secure authentication via system browser using Android App Links
- **Custom Tab Support** - Enhanced user experience with Chrome Custom Tabs

## Getting started

### Prerequisites

- Android API Level 23 (Marshmallow) or higher
- IBM Verify tenant or IBM Verify Identity Access server
- OAuth 2.0 / OIDC configured application

### Integrating with your project

See [here](../../README.md#integrating-with-your-project)

### API documentation

The Authentication SDK API can be reviewed [here](https://ibm-verify.github.io/android/authentication/docs/).

## Usage

### Basic OAuth 2.0 Setup

Initialize the `OAuthProvider` with your client credentials:

```kotlin
import com.ibm.security.verifysdk.authentication.OAuthProvider

val oauthProvider = OAuthProvider(
    clientId = "your-client-id",
    clientSecret = "your-client-secret" // Optional for public clients
)
```

### Authorization Code Flow

The authorization code flow is the recommended approach for mobile applications. It uses the system browser for authentication and returns an authorization code that is exchanged for tokens.

#### Step 1: Configure Deep Links

Configure your app to handle OAuth redirect callbacks. See the [Authorization Code Flow Demo](../../examples/authcodeflow_demo/README.md#deep-link-configuration-oauth-redirect-handling) for detailed setup instructions.

#### Step 2: Generate PKCE Parameters (Recommended)

```kotlin
import com.ibm.security.verifysdk.authentication.PKCEHelper

// Generate code verifier and challenge
val codeVerifier = PKCEHelper.generateCodeVerifier()
val codeChallenge = PKCEHelper.generateCodeChallenge(codeVerifier)
```

#### Step 3: Initiate Browser-Based Authorization

Use the `authorizeWithBrowser` function to launch the system browser and obtain an authorization code:

```kotlin
import java.net.URL

lifecycleScope.launch {
    // Launch browser and get authorization code
    oauthProvider.authorizeWithBrowser(
        url = URL("https://your-server.com/oauth2/authorize"),
        redirectUrl = redirectUri,
        codeChallenge = codeChallenge,
        method = CodeChallengeMethod.S256,
        scope = arrayOf("openid", "profile"),
        activity = this@MainActivity
    )
        .onSuccess { authorizationCode ->
            println("Authorization code received: $authorizationCode")
            // Proceed to exchange code for tokens
        }
        .onFailure { error ->
            println("Authorization failed: ${error.message}")
        }
}
```

**Parameters**:
- `url`: The authorization endpoint URL
- `redirectUrl`: The redirect URI configured in your OAuth server
- `codeChallenge`: The PKCE code challenge (optional but recommended)
- `method`: The code challenge method (`S256` or `PLAIN`)
- `scope`: Array of requested scopes (defaults to `["openid"]`)
- `state`: Optional state parameter for CSRF protection
- `activity`: The ComponentActivity invoking this method

#### Step 4: Exchange Authorization Code for Tokens

After receiving the authorization code from `authorizeWithBrowser`, exchange it for tokens:

```kotlin
lifecycleScope.launch {
    oauthProvider.authorize(
        url = "https://your-server.com/oauth2/token",
        redirectUrl = redirectUri,
        authorizationCode = authorizationCode,
        codeVerifier = codeVerifier
    )
        .onSuccess { tokenInfo ->
            println("Access token: ${tokenInfo.accessToken}")
            println("Refresh token: ${tokenInfo.refreshToken}")
            println("ID token: ${tokenInfo.idToken}")
            println("Expires in: ${tokenInfo.expiresIn} seconds")
        }
        .onFailure { error ->
            println("Authorization failed: ${error.message}")
        }
}
```

### Password Grant Flow

For scenarios where the authorization code flow is not suitable:

```kotlin
lifecycleScope.launch {
    oauthProvider.authorize(
        url = "https://your-server.com/oauth2/token",
        username = "user@example.com",
        password = "password123"
    )
        .onSuccess { tokenInfo ->
            println("Access token: ${tokenInfo.accessToken}")
        }
        .onFailure { error ->
            println("Authentication failed: ${error.message}")
        }
}
```

### Token Refresh

Refresh an expired access token using a refresh token:

```kotlin
lifecycleScope.launch {
    oauthProvider.refresh(
        url = "https://your-server.com/oauth2/token",
        refreshToken = tokenInfo.refreshToken
    )
        .onSuccess { newTokenInfo ->
            println("New access token: ${newTokenInfo.accessToken}")
        }
        .onFailure { error ->
            println("Token refresh failed: ${error.message}")
        }
}
```

### OIDC Discovery

Automatically discover OAuth/OIDC endpoints:

```kotlin
import com.ibm.security.verifysdk.authentication.OIDCMetadataInfo

lifecycleScope.launch {
    OIDCMetadataInfo.discover("https://your-server.com")
        .onSuccess { metadata ->
            println("Authorization endpoint: ${metadata.authorizationEndpoint}")
            println("Token endpoint: ${metadata.tokenEndpoint}")
            println("Userinfo endpoint: ${metadata.userinfoEndpoint}")
            println("Supported scopes: ${metadata.scopesSupported}")
        }
        .onFailure { error ->
            println("Discovery failed: ${error.message}")
        }
}
```

### DPoP (Demonstrating Proof-of-Possession)

DPoP provides sender-constrained tokens for enhanced security. See [DPOP_USAGE.md](DPOP_USAGE.md) for comprehensive documentation.

#### Enable DPoP

```kotlin
val oauthProvider = OAuthProvider(
    clientId = "your-client-id"
)

// Enable DPoP
oauthProvider.useDPoP = true

// Optional: Use custom key alias
oauthProvider.dpopKeyAlias = "my-custom-dpop-key"
```

#### Authorization with DPoP

```kotlin
lifecycleScope.launch {
    oauthProvider.authorize(
        url = tokenEndpointUrl,
        redirectUrl = redirectUri,
        authorizationCode = code,
        codeVerifier = codeVerifier
    )
        .onSuccess { tokenInfo ->
            println("Token type: ${tokenInfo.tokenType}") // Should be "DPoP"
        }
}
```

#### Using DPoP Tokens with Resource Servers

```kotlin
import com.ibm.security.verifysdk.authentication.DPoPHelper

// Generate DPoP proof for API request
val dpopProof = DPoPHelper.generateDPoPToken(
    htu = "https://api.example.com/data",
    htm = "GET",
    accessToken = tokenInfo.accessToken
)

// Make authenticated request
val response = httpClient.get("https://api.example.com/data") {
    header("Authorization", "DPoP ${tokenInfo.accessToken}")
    header("DPoP", dpopProof)
}
```

### PKCE Helper Methods

The `PKCEHelper` class provides utility methods for PKCE:

```kotlin
import com.ibm.security.verifysdk.authentication.PKCEHelper

// Generate code verifier (43-128 characters)
val codeVerifier = PKCEHelper.generateCodeVerifier()

// Generate code challenge using S256 method
val codeChallenge = PKCEHelper.generateCodeChallenge(codeVerifier)
```

## Code Challenge Methods

The SDK supports both PKCE code challenge methods:

```kotlin
import com.ibm.security.verifysdk.authentication.CodeChallengeMethod

// S256 (SHA-256) - Recommended
val method = CodeChallengeMethod.S256

// Plain - Not recommended for production
val method = CodeChallengeMethod.PLAIN
```

## Token Information

The `TokenInfo` class contains the OAuth token response:

```kotlin
data class TokenInfo(
    val accessToken: String,
    val refreshToken: String?,
    val idToken: String?,
    val tokenType: String,
    val expiresIn: Int,
    val scope: String?
)
```

## Security Considerations

1. **Use PKCE**: Always use PKCE for authorization code flow in mobile apps
2. **Secure Storage**: Store tokens securely using Android Keystore or encrypted SharedPreferences
3. **Token Expiration**: Implement proper token refresh logic before tokens expire
4. **DPoP**: Consider using DPoP for enhanced token security
5. **Browser Security**: The SDK uses the system browser for authentication, which provides isolation from the app
6. **Deep Link Validation**: Validate redirect URIs and authorization codes

## Examples

- [Authorization Code Flow Demo](../../examples/authcodeflow_demo/) - Complete example with PKCE and OIDC support
- [DPoP Usage Guide](DPOP_USAGE.md) - Comprehensive DPoP implementation guide

## Requirements

- Android API Level 23 (Marshmallow) or higher
- Kotlin 1.9 or higher
- AndroidX libraries

## Dependencies

The Authentication SDK depends on:

- `com.ibm.security.verifysdk:core` - Core SDK functionality
- AndroidX AppCompat, Biometric, Browser, and Core KTX
- Ktor for HTTP networking
- kotlinx-serialization for JSON handling
- jose4j for JWT/JWE/JWS operations

## Troubleshooting

### Authorization Code Not Received

- Verify deep link configuration in AndroidManifest.xml
- Check that redirect URI matches OAuth server configuration
- Test deep link with `adb shell am start -a android.intent.action.VIEW -d "your-redirect-uri"`

### Token Request Fails

- Verify client ID and client secret (if applicable)
- Check that code verifier matches the code challenge used in authorization
- Ensure token endpoint URL is correct

### DPoP Issues

- Verify device supports Android KeyStore (API 23+)
- Check that authorization server supports DPoP
- Ensure `htu` and `htm` claims match the request exactly

## License

This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.