# IBM Verify SDK - MFA Module

**Version:** 3.2.0
**Package:** `com.ibm.security.verifysdk.mfa`

## Overview

The MFA (Multi-Factor Authentication) module provides comprehensive support for cloud-based and on-premise multi-factor authentication, including:

- **Token Management** - OAuth 2.0 token refresh with automatic persistence
- **Transaction Handling** - Push-based transaction verification
- **TOTP/HOTP** - Time-based and counter-based one-time passwords
- **Biometric Authentication** - Unified biometric factor (fingerprint/face)
- **User Presence** - Device-based authentication factors

## Recent Improvements (v3.2.0)

- **Performance Optimizations**: Lazy logging reduces memory allocations in production builds
- **JSON Standardization**: Type-safe parsing with `kotlinx.serialization`
- **Improved Test Coverage**: Comprehensive test cases for TokenPersistenceCallback and TransactionData
- **Thread Safety**: Immutable service design ensures thread-safe operations
- **Error Handling**: Structured exceptions with better error chaining

## Key Components

### Services

#### CloudAuthenticatorService
Immutable service for cloud-based MFA operations (IBM Verify SaaS).

```kotlin
val service = CloudAuthenticatorService(
    _accessToken = authenticator.token.accessToken,
    _refreshUri = authenticator.refreshUri,
    _transactionUri = authenticator.transactionUri,
    _authenticatorId = authenticator.id,
    httpClient = NetworkHelper.getInstance,
    persistenceCallback = repository
)
```

**Key Features:**
- Immutable value object design (thread-safe)
- Automatic token persistence via callback
- Push transaction support
- Token refresh with blocking persistence

#### OnPremiseAuthenticatorService
Service for on-premise MFA operations (IBM Verify Access).

```kotlin
val service = OnPremiseAuthenticatorService(
    _accessToken = authenticator.token.accessToken,
    _refreshUri = authenticator.refreshUri,
    _transactionUri = authenticator.transactionUri,
    _authenticatorId = authenticator.id,
    _clientId = authenticator.clientId,
    _ignoreSslCertificate = false,
    httpClient = NetworkHelper.getInstance,
    persistenceCallback = repository
)
```

### Controllers

#### MFARegistrationController
Handles authenticator registration via QR code scanning.

```kotlin
val controller = MFARegistrationController(qrCodeData)
val result = controller.initiate(
    accountName = "user@example.com",
    pushToken = fcmToken,
    skipTotpEnrollment = false,
    httpClient = NetworkHelper.getInstance
)
```

#### MFAServiceController
Factory for creating service instances from authenticator descriptors.

```kotlin
val controller = MFAServiceController(authenticator)
val service = controller.initiate()
```

### Interfaces

#### TokenPersistenceCallback
**CRITICAL:** Implement this interface to enable automatic token persistence.

```kotlin
class Repository : TokenPersistenceCallback {
    override suspend fun onTokenRefreshed(
        authenticatorId: String,
        newToken: TokenInfo
    ): Result<Unit> {
        return try {
            database.updateToken(authenticatorId, newToken)
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
```

**Why This Matters:**
- Tokens MUST be persisted BEFORE any API call uses them
- Prevents "hosed authenticator" scenario (permanent corruption)
- Blocking persistence ensures atomicity

## Architecture Patterns

### Immutable Service Design

Services are **immutable value objects** that represent a point-in-time snapshot:

```kotlin
// 1. Create service with current token
val service = CloudAuthenticatorService(...)

// 2. Use for operations
service.nextTransaction()
service.completeTransaction(...)

// 3. After token refresh, create NEW service
service.refreshToken(...).onSuccess { newToken ->
    val newService = CloudAuthenticatorService(
        _accessToken = newToken.accessToken,  // New token
        ...
    )
    // Use newService for subsequent operations
}
```

**Benefits:**
- Thread-safe by design (no synchronization needed)
- Clear lifecycle and ownership
- No hidden state mutations
- Lightweight to create (~1ms)

### Token Management Pattern

```kotlin
suspend fun <T> executeWithTokenManagement(
    authenticator: MFAAuthenticatorDescriptor,
    operation: suspend (MFAServiceDescriptor) -> Result<T>
): Result<T> {
    // 1. Proactive refresh if token near expiry
    if (authenticator.token.shouldRefresh()) {
        refreshAndSaveToken(authenticator)
    }
    
    // 2. Create service and execute
    val service = createService(authenticator)
    val result = operation(service)
    
    // 3. Reactive refresh on 401
    if (result.isFailure && is401Error(result)) {
        refreshAndSaveToken(authenticator)
        val newService = createService(authenticator)
        return operation(newService)
    }
    
    return result
}
```

### Transaction State Management

Applications track transactions locally, not in the service:

```kotlin
// ✅ Correct: App tracks transaction
var currentTransaction: PendingTransactionInfo? = null

service.nextTransaction().onSuccess { (transactions, count) ->
    currentTransaction = transactions.firstOrNull()
}

// Later, pass transaction explicitly
service.completeTransaction(
    transaction = currentTransaction!!,
    userAction = UserAction.VERIFY,
    signedData = signature
)
```

## Critical Concepts

### 🔴 Token Persistence

**THE MOST IMPORTANT RULE:**
> Tokens MUST be persisted to database BEFORE any API call that uses them.

**Why:**
1. Server receives API call with new token → marks it as active
2. Server invalidates old token
3. If app crashes before saving new token → authenticator is permanently broken
4. On restart, old token is loaded → all API calls fail with 401

**Solution:**
- Implement `TokenPersistenceCallback`
- SDK blocks until persistence completes
- Refresh only succeeds if persistence succeeds

### Thread Safety

- **Services:** Thread-safe (immutable state)
- **Token Refresh:** Use `Mutex` to prevent concurrent refreshes
- **Transactions:** Application manages state (not service)

### Error Handling

```kotlin
service.refreshToken(...).fold(
    onSuccess = { newToken ->
        // Token refreshed and persisted successfully
    },
    onFailure = { error ->
        when {
            error.message?.contains("401") == true -> {
                // Refresh token expired - need re-registration
            }
            error.message?.contains("persistence failed") == true -> {
                // Database error - old token still valid, can retry
            }
            else -> {
                // Network or server error - can retry later
            }
        }
    }
)
```

## Build Configuration

### AGP 9.0+ Compatibility

The MFA module is compatible with Android Gradle Plugin 9.0+:

- ✅ Kotlin support is built into AGP 9.0+ (no separate plugin needed)
- ✅ Uses `kotlin.jvmToolchain(17)` instead of deprecated `kotlinOptions`
- ✅ Minimum SDK: 29 (Android 10.0)
- ✅ Target SDK: 36 (Android 16)

### Dependencies

```kotlin
dependencies {
    implementation(project(":sdk:mfa"))
    
    // Required for push notifications
    implementation(platform("com.google.firebase:firebase-bom:34.11.0"))
    implementation("com.google.firebase:firebase-messaging")
}
```

## Usage Examples

### Complete Registration Flow

```kotlin
// 1. Scan QR code
val qrData = scanQRCode()

// 2. Initialize registration
val controller = MFARegistrationController(qrData)

// 3. Register authenticator
val result = controller.initiate(
    accountName = "user@example.com",
    pushToken = getFCMToken(),
    skipTotpEnrollment = false
)

result.onSuccess { authenticator ->
    // 4. Save to database
    database.saveAuthenticator(authenticator)
    
    // 5. Enroll biometric (optional)
    controller.enrollBiometric(
        activity = this,
        authenticator = authenticator,
        factorId = authenticator.biometric?.id
    )
}
```

### Complete Transaction Flow

```kotlin
// 1. Create service with token management
val service = createServiceWithTokenManagement(authenticator)

// 2. Fetch pending transaction
service.nextTransaction().onSuccess { (transactions, count) ->
    val transaction = transactions.firstOrNull()
    
    if (transaction != null) {
        // 3. Show transaction to user
        showTransactionDialog(transaction)
        
        // 4. Complete transaction
        service.completeTransaction(
            transaction = transaction,
            userAction = UserAction.VERIFY,
            signedData = signTransaction(transaction)
        )
    }
}
```

## Testing

### Unit Tests

```kotlin
@Test
fun `token refresh persists before returning success`() = runBlocking {
    val mockCallback = mockk<TokenPersistenceCallback>()
    coEvery { mockCallback.onTokenRefreshed(any(), any()) } returns Result.success(Unit)
    
    val service = CloudAuthenticatorService(
        _accessToken = "old-token",
        _refreshUri = URL("https://example.com/refresh"),
        _transactionUri = URL("https://example.com/transactions"),
        _authenticatorId = "auth-id",
        httpClient = mockHttpClient,
        persistenceCallback = mockCallback
    )
    
    service.refreshToken("refresh-token", null)
    
    coVerify { mockCallback.onTokenRefreshed("auth-id", any()) }
}
```

## Documentation

- **SDK Usage Guide:** `/docs/SDK-USAGE-GUIDE.md`
- **Token Persistence Fix:** `/docs/token-persistence-critical-fix.md`
- **Service Design Analysis:** `/docs/stateless-vs-stateful-service-analysis.md`
- **Dependency Injection:** `/docs/network-helper-dependency-injection-analysis.md`
- **JSON Standardization:** `/docs/json-library-standardization-analysis.md`

## Migration Notes

### From v3.0.x to v3.1.x

**Breaking Changes:**
- `FactorType.Face` and `FactorType.Fingerprint` consolidated into `FactorType.Biometric`
- Exception-based error handling (replaced error classes with exceptions)
- `nextTransaction()` returns `Pair<List<PendingTransactionInfo>, Int>` (was single transaction)

**New Features:**
- Blocking token persistence (prevents authenticator corruption)
- `HttpClient` constructor injection (better testability)
- HOTP `generatePasscode(incrementCounter: Boolean)` for preview
- Improved thread safety with immutable services

**Deprecations:**
- None (clean API in 3.1.x)

## Support

- **Issues:** Report bugs via GitHub Issues
- **Documentation:** See `/docs` directory
- **Examples:** See `/examples/mfa_demo` for complete implementation

---

**Module Version:** 3.2.0
**Last Updated:** 2026-04-08
**Minimum Android SDK:** 29
**Target Android SDK:** 36