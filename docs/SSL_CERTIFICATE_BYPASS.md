# SSL Certificate Bypass for On-Premise Deployments

This document describes the SSL certificate bypass feature for IBM Verify SDK on-premise deployments.

## Overview

On-premise IBM Verify Access deployments may use self-signed certificates or certificates issued by private Certificate Authorities (CAs) that are not trusted by the Android system. The SDK provides a controlled mechanism to bypass SSL certificate validation for specific authenticators while maintaining overall application security.

## Two-Level Security Model

SSL certificate bypass requires **both** conditions to be met:

### 1. QR Code Level (Authenticator-Specific)

The QR code scanned during registration includes an `ignoreSSLCertificate` flag:

```json
{
  "code": "ABC123",
  "details_url": "https://onprem.example.com/...",
  "options": "ignoreSslCerts=true",
  "client_id": "..."
}
```

This flag indicates that **this specific authenticator** requires SSL bypass.

### 2. App Level (Permission Grant)

The application must explicitly enable SSL bypass by setting:

```kotlin
NetworkHelper.allowInsecureSSL = true
```

This grants **app-wide permission** for SSL bypass when requested by authenticators.

## Security Rationale

This two-level model provides defense-in-depth:

- **QR Code Level**: Prevents accidental SSL bypass for cloud authenticators
- **App Level**: Gives the application control over security policy
- **Authenticator Affinity**: SSL settings are bound to specific authenticators, not global

If a QR code requests SSL bypass but the app hasn't enabled it, registration will fail with an exception. This prevents:
- Accidental SSL bypass in production apps
- Man-in-the-middle attacks via malicious QR codes
- Unintended security policy violations

## Implementation Details

### Cloud vs On-Premise Behavior

| Provider | SSL Bypass Support | Default HTTP Client |
|----------|-------------------|---------------------|
| `CloudRegistrationProvider` | ❌ No | `NetworkHelper.getInstance` (secure) |
| `OnPremiseRegistrationProvider` | ✅ Yes | Configured during `initiate()` based on `ignoreSSLCertificate` |

### HTTP Client Affinity

For on-premise registrations, the HTTP client is created during `initiate()` and stored internally:

```kotlin
// In OnPremiseRegistrationProvider.initiate()
registrationHttpClient = if (initializationInfo.ignoreSSLCertificate) {
    NetworkHelper.createInsecureClient()  // Bypasses SSL validation
} else {
    httpClient  // Uses provided secure client
}
```

All subsequent operations (`enrollBiometric`, `enrollUserPresence`, `enrollOneTimePasscode`, `finalize`) use this stored client to ensure SSL settings are preserved throughout the registration flow.

### Method Parameters

All enrollment methods accept an optional `httpClient` parameter:

```kotlin
suspend fun enrollBiometric(httpClient: HttpClient? = null)
suspend fun enrollUserPresence(httpClient: HttpClient? = null)
suspend fun enrollOneTimePasscode(httpClient: HttpClient? = null): OTPAuthenticator
suspend fun finalize(httpClient: HttpClient? = null): Result<MFAAuthenticatorDescriptor>
```

**Behavior by Provider:**

- **Cloud**: `httpClient ?: NetworkHelper.getInstance` (always secure)
- **OnPremise**: `httpClient ?: registrationHttpClient` (respects SSL bypass settings)

The parameter allows for testing flexibility (e.g., mock HTTP engines) while ensuring correct default behavior.

## Usage Examples

### Basic On-Premise Registration with SSL Bypass

```kotlin
// 1. Enable SSL bypass at app level
NetworkHelper.allowInsecureSSL = true

// 2. Scan QR code with ignoreSSLCertificate=true
val qrData = """
{
  "code": "ABC123",
  "details_url": "https://onprem.example.com/...",
  "options": "ignoreSslCerts=true",
  "client_id": "..."
}
"""

// 3. Create provider
val provider = OnPremiseRegistrationProvider(qrData)

// 4. Initiate - automatically creates insecure client
provider.initiate(
    accountName = "John Doe",
    pushToken = "fcm-token-123"
).onSuccess {
    // 5. Enroll factors - automatically uses insecure client
    provider.enrollBiometric()
    provider.enrollUserPresence()
    
    // 6. Finalize - uses same insecure client
    provider.finalize().onSuccess { authenticator ->
        // Registration complete
    }
}
```

### On-Premise Registration WITHOUT SSL Bypass

```kotlin
// No need to set NetworkHelper.allowInsecureSSL

// QR code without ignoreSSLCertificate flag
val qrData = """
{
  "code": "ABC123",
  "details_url": "https://onprem.example.com/...",
  "client_id": "..."
}
"""

val provider = OnPremiseRegistrationProvider(qrData)

// Uses secure client throughout
provider.initiate(accountName, pushToken).onSuccess {
    provider.enrollBiometric()
    provider.finalize()
}
```

### Cloud Registration (Always Secure)

```kotlin
// Cloud registrations never use SSL bypass
val qrData = """
{
  "code": "ABC123",
  "details_url": "https://tenant.verify.ibm.com/...",
  "client_id": "..."
}
"""

val provider = CloudRegistrationProvider(qrData)

// Always uses NetworkHelper.getInstance (secure)
provider.initiate(accountName, pushToken).onSuccess {
    provider.enrollBiometric()
    provider.finalize()
}
```

## Error Handling

### SSL Bypass Not Allowed

If a QR code requests SSL bypass but the app hasn't enabled it:

```kotlin
try {
    provider.initiate(accountName, pushToken)
} catch (e: Exception) {
    // Exception thrown: SSL bypass requested but not allowed
    // Enable with: NetworkHelper.allowInsecureSSL = true
}
```

### SSL Certificate Validation Failure

If SSL bypass is not enabled and the certificate is invalid:

```kotlin
try {
    provider.initiate(accountName, pushToken)
} catch (e: Exception) {
    // Network error: SSL certificate validation failed
    // Options:
    // 1. Install valid certificate on server
    // 2. Enable SSL bypass (if appropriate)
}
```

## Testing

### Unit Tests with Mock HTTP Client

The `httpClient` parameter allows injecting mock clients for testing:

```kotlin
@Test
fun testEnrollment() = runTest {
    val mockEngine = MockEngine { request ->
        respond(
            content = """{"status":"success"}""",
            status = HttpStatusCode.OK,
            headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
    }
    
    val mockClient = HttpClient(mockEngine)
    
    // Override default client for testing
    provider.enrollBiometric(httpClient = mockClient)
}
```

### Integration Tests with Self-Signed Certificates

```kotlin
@Test
fun testSSLBypass() = runTest {
    // Enable SSL bypass for test
    NetworkHelper.allowInsecureSSL = true
    
    val provider = OnPremiseRegistrationProvider(qrDataWithSSLBypass)
    
    // Should succeed with self-signed certificate
    val result = provider.initiate(accountName, pushToken)
    assertTrue(result.isSuccess)
    
    // Cleanup
    NetworkHelper.allowInsecureSSL = false
}
```

## Security Considerations

### When to Enable SSL Bypass

✅ **Appropriate Use Cases:**
- Development/testing environments with self-signed certificates
- Enterprise deployments with private CAs
- Controlled on-premise environments

❌ **Inappropriate Use Cases:**
- Production apps connecting to public internet
- Cloud-based IBM Verify instances
- Any scenario where certificate validation is feasible

### Best Practices

1. **Minimize Scope**: Only enable SSL bypass when absolutely necessary
2. **User Awareness**: Inform users when SSL bypass is active
3. **Audit Logging**: Log when SSL bypass is used
4. **Certificate Pinning**: Consider certificate pinning as an alternative
5. **Time-Limited**: Disable SSL bypass after registration if possible

### Production Recommendations

For production deployments, prefer these alternatives to SSL bypass:

1. **Install Valid Certificates**: Use certificates from trusted CAs
2. **Custom Trust Store**: Add private CA certificates to Android's trust store
3. **Certificate Pinning**: Pin specific certificates in the app
4. **Network Security Config**: Use Android's network security configuration

## API Reference

### NetworkHelper

```kotlin
object NetworkHelper {
    /**
     * Global flag to allow SSL certificate bypass.
     * Must be set to true before creating insecure clients.
     */
    var allowInsecureSSL: Boolean = false
    
    /**
     * Creates an HTTP client that bypasses SSL certificate validation.
     * Requires allowInsecureSSL = true.
     */
    fun createInsecureClient(): HttpClient
    
    /**
     * Default secure HTTP client instance.
     */
    val getInstance: HttpClient
}
```

### OnPremiseRegistrationProvider

```kotlin
class OnPremiseRegistrationProvider(data: String) : MFARegistrationDescriptor {
    /**
     * Initiates registration and creates appropriate HTTP client.
     * If ignoreSSLCertificate=true in QR code, creates insecure client.
     */
    suspend fun initiate(
        accountName: String,
        pushToken: String?,
        additionalHeaders: HashMap<String, String>? = null,
        httpClient: HttpClient = NetworkHelper.getInstance
    ): Result<OnPremiseRegistrationProviderResultData>
    
    // All enrollment methods use stored registrationHttpClient by default
    suspend fun enrollBiometric(httpClient: HttpClient? = null)
    suspend fun enrollUserPresence(httpClient: HttpClient? = null)
    suspend fun enrollOneTimePasscode(httpClient: HttpClient? = null): OTPAuthenticator
    suspend fun finalize(httpClient: HttpClient? = null): Result<MFAAuthenticatorDescriptor>
}
```

## Related Documentation

- [NetworkHelper API Documentation](../sdk/core/src/main/java/com/ibm/security/verifysdk/core/helper/NetworkHelper.kt)
- [OnPremiseRegistrationProvider API Documentation](../sdk/mfa/src/main/java/com/ibm/security/verifysdk/mfa/api/OnPremiseRegistrationProvider.kt)
- [CloudRegistrationProvider API Documentation](../sdk/mfa/src/main/java/com/ibm/security/verifysdk/mfa/api/CloudRegistrationProvider.kt)
- [MFARegistrationDescriptor Interface](../sdk/mfa/src/main/java/com/ibm/security/verifysdk/mfa/MFARegistrationDescriptor.kt)

## Changelog

### Version 3.x
- Implemented two-level security model for SSL bypass
- Added `NetworkHelper.allowInsecureSSL` app-level permission
- Added `ignoreSSLCertificate` flag support in QR codes
- Implemented HTTP client affinity for on-premise registrations
- Added nullable `httpClient` parameters for testing flexibility