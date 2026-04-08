# IBM Verify SDK Android Agent

This file describes the structure and components of the IBM Verify SDK for Android project.

## Project Overview

The IBM Verify SDK for Android is a collection of libraries that provide authentication and security features for Android applications. It's structured as a multi-module Gradle project.

## Module Structure

The project is divided into SDK modules and example applications:

### SDK Modules (`/sdk`)

- **`:sdk:core`**: Provides common functionality such as Keystore helpers, networking utilities, and logging extensions. Includes `VerifySdkException` and `AuthenticationException` for structured error handling.
- **`:sdk:authentication`**: Implements OAuth 2.0 and OpenID Connect (OIDC) protocols for mobile applications.
- **`:sdk:mfa`**: Handles Multi-Factor Authentication, including authenticator registration, TOTP, and push-based transaction processing.
- **`:sdk:fido2`**: A native implementation of FIDO2/WebAuthn ceremonies (attestation and assertion).
- **`:sdk:adaptive`**: Provides device assessment and risk evaluation based on cloud risk policies.

### Example Applications (`/examples`)

- **`:examples:mfa_demo`**: Demonstrates the use of the MFA SDK for registration and transaction verification.
- **`:examples:authcodeflow_demo`**: Shows how to use the Authentication SDK with the OAuth 2.0 Authorization Code flow.
- **`:examples:dpop_demo`**: Demonstrates Demonstrating Proof-of-Possession (DPoP) at the Application Layer.
- **`:examples:fido2_demo`**: Showcases FIDO2 registration and authentication.

## Recent Changes (Release 3.2.0)

- **Exception-Based Error Handling**: Replaced error classes with exceptions (`MFARegistrationException`, `MFAServiceException`) for better error chaining.
- **Biometric Factor Consolidation**: Unified face and fingerprint factors into a single `FactorType.Biometric`.
- **HOTP Enhancements**: Added `generatePasscode(incrementCounter: Boolean)` to allow previewing passcodes.
- **Thread-Safe Networking**: Improved `HttpClient` initialization and lifecycle management in the Core SDK.
- **Critical Token Persistence Fix**: Implemented blocking token persistence to prevent "hosed authenticator" scenario where app crashes after token refresh but before persistence.
- **HttpClient Constructor Injection**: Moved `HttpClient` from method parameters to constructor for better encapsulation and testability.
- **JSON Library Standardization**: Standardized on `kotlinx.serialization` throughout, removing `org.json` dependencies for type safety.
- **Immutable Service Design**: Clarified that services are immutable value objects that must be recreated when tokens change.
- **Certificate Transparency Support**: Added optional CT verification to NetworkHelper using interceptor method (SDK best practice).
- **Performance Optimizations**: COSEKey lazy initialization (~95% improvement), lazy logging, StandardCharsets usage.
- **Test Coverage Improvements**: Added comprehensive test cases for TokenPersistenceCallback, TransactionData, KeystoreHelper, and other core components.
- **Test Utils Module Removal**: Eliminated the `:sdk:test_utils` module by moving test utilities to module-specific test sources for better encapsulation.
- **Integration Test Suite**: Added `CloudAuthenticatorIntegrationTest` based on real network traces to validate complete MFA flows.
- **Deprecation Fixes**: Replaced deprecated Ktor Base64 utilities with Kotlin stdlib `Base64.Default.decode()` in FIDO2 demo; migrated from deprecated `LifecycleObserver` with `@OnLifecycleEvent` to `DefaultLifecycleObserver` in Adaptive SDK for better type safety and compile-time checking.

## Build and Test Commands

### Building

To build all modules in the project:
```bash
./gradlew assemble
```

To build a specific module (e.g., MFA):
```bash
./gradlew :sdk:mfa:assembleDebug
```

### Testing

To run all unit tests:
```bash
./gradlew test
```

To run unit tests for a specific module:
```bash
./gradlew :sdk:mfa:testDebugUnitTest
```

To run Android instrumentation tests (requires a device/emulator):
```bash
./gradlew connectedAndroidTest
```

## Development Environment Notes

### macOS Specific Configuration

Due to known issues with spawning helper processes on macOS, the following settings are maintained in `gradle.properties`:

- `kotlin.compiler.execution.strategy=in-process`: Runs the Kotlin compiler within the Gradle process.
- `android.enableAapt2Daemon=false`: Disables the AAPT2 daemon to prevent resource linking failures.

### Dependency Management

The project uses a Version Catalog (`gradle/libs.versions.toml`) for managing dependencies and versions across all modules.

## Key Components

- **MFARegistrationController**: Used in the MFA demo to initiate and finalize authenticator registration via QR codes.
- **MFAServiceController**: Manages the lifecycle of MFA transactions and creates service instances with proper configuration.
- **KeystoreHelper**: A core utility for secure key management using the Android Keystore system.
- **CloudAuthenticatorService**: Immutable service instance for cloud-based MFA operations. Must be recreated when token is refreshed.
- **OnPremiseAuthenticatorService**: Immutable service instance for on-premise MFA operations.
- **TokenPersistenceCallback**: Interface for blocking token persistence to ensure data integrity.
- **NetworkHelper**: Singleton providing HTTP client with optional Certificate Transparency verification.
- **COSEKey**: FIDO2 COSE key representation with lazy CBOR serialization for improved performance.

## Versioning

Current Version: `3.2.0` (Code: `119`)
Minimum Android SDK: 29 (Android 10.0)
Target Android SDK: 36 (Android 16)

## Architecture & Design Patterns

### 1. Token Persistence (CRITICAL)

**Problem:** If the app crashes after a token refresh but before the new token is persisted to the database, the authenticator becomes permanently unusable. This happens because:
1. Server receives API call with new token and marks it as active
2. Server invalidates the old token
3. App crashes before saving new token to database
4. On restart, old token is loaded from database
5. All API calls fail with 401 Unauthorized

**Solution:** Blocking token persistence ensures atomicity - token refresh only succeeds if persistence succeeds:

```kotlin
// In CloudAuthenticatorService.refreshToken()
persistenceCallback?.let { callback ->
    val persistResult = callback.onTokenRefreshed(authenticatorId, newTokenInfo)
    persistResult.onFailure { error ->
        Log.e(TAG, "CRITICAL: Token persistence failed")
        return Result.failure(
            Exception("Token refresh succeeded but persistence failed: ${error.message}", error)
        )
    }
    Log.d(TAG, "Token persisted successfully")
}
```

**Key Principles:**
- Token persistence is **blocking and atomic** (waits for database save to complete)
- Refresh fails if persistence fails (fail-fast approach)
- Token is saved **before** any subsequent API call that uses it
- Prevents partial state where server has new token but app doesn't

**Implementation Location:** `CloudAuthenticatorService.kt` lines 287-295

### 2. Dependency Injection Pattern

**Recommendation:** Use constructor injection for `HttpClient` instead of method parameters.

```kotlin
// ✅ Recommended: Constructor injection
class CloudAuthenticatorService(
    private val _accessToken: String,
    private val _refreshUri: URL,
    private val _transactionUri: URL,
    private val _authenticatorId: String,
    internal val httpClient: HttpClient,
    private val persistenceCallback: TokenPersistenceCallback? = null
) : MFAServiceDescriptor {
    
    suspend fun refreshToken(
        refreshToken: String,
        additionalData: Map<String, Any>?
    ): Result<TokenInfo> {
        // Use this.httpClient
    }
}

// ❌ Avoid: Method-level parameters
suspend fun refreshToken(
    refreshToken: String,
    additionalData: Map<String, Any>?,
    httpClient: HttpClient = NetworkHelper.getInstance  // Clutters API
): Result<TokenInfo>
```

**Benefits:**
- **Cleaner API**: Method signatures focus on business logic, not technical details
- **Better Testability**: Mock once in constructor, all methods use it automatically
- **Consistency**: Same client for all operations, predictable behavior
- **Better Encapsulation**: HTTP client is implementation detail, hidden from public API
- **Performance**: `getInstance` called once, not per method

**Implementation Location:** `CloudAuthenticatorService.kt` line 166

### 3. JSON Library Standardization

**Standard:** Use `kotlinx.serialization` throughout the SDK, avoid `org.json`.

```kotlin
// ✅ Recommended: kotlinx.serialization with type-safe data classes
@Serializable
data class TransactionData(
    @SerialName("message") val message: String? = null,
    @SerialName("originIpAddress") val originIpAddress: String? = null,
    @SerialName("originUserAgent") val originUserAgent: String? = null,
    @SerialName("additionalData") val additionalData: List<AdditionalDataItem>? = null
)

@Serializable
data class AdditionalDataItem(
    @SerialName("name") val name: String,
    @SerialName("value") val value: String
)

// Parse JSON
val data = Json.decodeFromString<TransactionData>(jsonString)
val message = data.message ?: "default"

// ❌ Avoid: org.json with imperative parsing
val json = JSONObject(jsonString)
val message = json.optString("message", "default")  // No type safety
json.has("field")  // Manual field checking
json.remove("field")  // Imperative mutations
```

**Benefits:**
- **Type Safety**: Compile-time checking of field names and types
- **Null Safety**: Kotlin's null safety enforced, no `optString()` surprises
- **Reduced Code**: Declarative parsing vs imperative (60+ lines → 40 lines)
- **Better Errors**: Clear error messages, single try-catch for entire parsing
- **Consistency**: Same JSON library throughout codebase
- **Performance**: Optimized for Kotlin, no reflection overhead

**Implementation Location:** `CloudAuthenticatorService.kt` lines 630-694, `TransactionData.kt`

### 4. Service Design Philosophy

**Pattern:** Immutable Service Instances (not truly stateless)

Services are **immutable value objects** that represent a snapshot of authenticator state at a specific point in time. They are NOT traditional stateful services that maintain and update their state.

```kotlin
// Services are immutable value objects
class CloudAuthenticatorService(
    private val _accessToken: String,  // Immutable
    private val _refreshUri: URL,      // Immutable
    private val _transactionUri: URL,  // Immutable
    private val _authenticatorId: String  // Immutable
) : MFAServiceDescriptor

// Lifecycle: Create → Use → Discard → Recreate with new token
// 1. Create service with current token
val service = CloudAuthenticatorService(
    _accessToken = authenticator.token.accessToken,
    _refreshUri = authenticator.refreshUri,
    _transactionUri = authenticator.transactionUri,
    _authenticatorId = authenticator.id,
    httpClient = NetworkHelper.getInstance,
    persistenceCallback = repository
)

// 2. Use service for operations
service.nextTransaction()
service.completeTransaction(...)

// 3. If token is refreshed, create NEW service
service.refreshToken(...).onSuccess { newToken ->
    // This service is now obsolete!
    val newService = CloudAuthenticatorService(
        _accessToken = newToken.accessToken,  // New token
        _refreshUri = authenticator.refreshUri,
        _transactionUri = authenticator.transactionUri,
        _authenticatorId = authenticator.id,
        httpClient = NetworkHelper.getInstance,
        persistenceCallback = repository
    )
    // Use newService for subsequent operations
}
```

**Key Principles:**
- Services are **immutable value objects**, not stateless
- **Thread-safe by design**: No synchronization needed, multiple threads can safely call methods concurrently
- **Short-lived**: Created per operation or set of operations
- **Must be recreated** when token changes (service becomes obsolete)
- **Lightweight**: Creating new instances is fast (~1ms, just property assignment)

**Why Immutable?**
- **Thread Safety**: No race conditions or data corruption without locks
- **Clear Semantics**: Service represents point-in-time snapshot, explicit lifecycle
- **Simple**: No hidden state mutations, easy to reason about
- **Lightweight**: No expensive initialization or resource allocation

**Correct Terminology:**
- ✅ "Immutable service instance"
- ✅ "Short-lived stateful proxy"
- ✅ "Value object service"
- ❌ NOT "Stateless service" (holds immutable state)

### 5. Transaction State Management

**Pattern:** Applications track current transaction locally, not in the service.

```kotlin
// ✅ Application tracks transaction
class MainActivity {
    private var currentPendingTransaction: PendingTransactionInfo? = null
    
    fun checkPendingTransaction() {
        service.nextTransaction().onSuccess { (transaction, count) ->
            currentPendingTransaction = transaction  // Store locally
            // Update UI with transaction details
        }
    }
    
    fun completeTransaction() {
        val transaction = currentPendingTransaction ?: return
        service.completeTransaction(
            transaction = transaction,  // Pass explicitly
            userAction = UserAction.VERIFY,
            factorType = factorType
        )
    }
}

// ❌ Service does NOT track current transaction
// service.currentPendingTransaction  // This property was removed in 3.1.x
```

**Key Principles:**
- Services are immutable and don't track mutable state
- Applications manage transaction lifecycle
- Transactions passed explicitly to methods
- Clear separation of concerns (service handles API, app handles state)

**Benefits:**
- **Immutability**: Services remain immutable
- **Flexibility**: Apps can manage multiple transactions
- **Clarity**: Explicit transaction passing makes flow clear
- **Testability**: Easier to test with explicit parameters

## Best Practices

### Token Management
1. **Always use `TokenPersistenceCallback`** for automatic token persistence
2. **Implement blocking persistence**: Wait for database save to complete before returning success
3. **Use `Mutex`** to prevent concurrent token refreshes for same authenticator
4. **Create new service instance** after token refresh (don't reuse old instance)

### Service Lifecycle
1. **Create** service instance with current token
2. **Use** for one or more operations
3. **Discard** if token refreshes
4. **Recreate** new instance with new token
5. **Don't reuse** service after token changes

### Testing
1. **Mock `HttpClient` in constructor** for unit tests (not per method)
2. **Test token persistence failure** scenarios explicitly
3. **Verify service immutability** (no state changes)
4. **Test concurrent operations** (should be thread-safe)
5. **Use inline Json configuration** in test files that need custom serialization:
   ```kotlin
   private val json = Json {
       encodeDefaults = true
       explicitNulls = false
       ignoreUnknownKeys = true
       isLenient = true
   }
   ```

### Error Handling
1. **Use structured exceptions** (`MFAServiceException`, `MFARegistrationException`)
2. **Chain exceptions** for better debugging context
3. **Handle token persistence failures** explicitly (don't ignore)
4. **Provide meaningful error messages** for troubleshooting

### JSON Parsing
1. **Define `@Serializable` data classes** for all JSON structures
2. **Use `@SerialName`** for field mapping
3. **Handle nullability explicitly** with Kotlin's type system
4. **Wrap parsing in try-catch** with graceful degradation
5. **Avoid `org.json`** - use `kotlinx.serialization` instead

### Certificate Transparency
1. **Use interceptor method** for SDK implementations (not Security Provider)
2. **Set via property**: `NetworkHelper.certificateTransparencyInterceptor`
3. **Scoped to SDK**: Won't conflict with client app's CT configuration
4. **Optional**: Disabled by default for backward compatibility
5. **See documentation**: `docs/CERTIFICATE_TRANSPARENCY_GUIDE.md`

### Performance Optimization
1. **Use lazy initialization** for expensive operations (e.g., COSEKey.toCBOR)
2. **Use lazy logging** to prevent string allocation when logging disabled
3. **Explicit charsets**: Always specify `StandardCharsets.UTF_8` for platform independence
4. **Shared instances**: Reuse expensive objects (e.g., CBORMapper) across instances
5. **Profile before optimizing**: Measure impact of changes

### Deprecation Management
1. **Use Kotlin stdlib over third-party utilities**: Prefer `kotlin.io.encoding.Base64` over Ktor's deprecated Base64 utilities
2. **Migrate to modern lifecycle APIs**: Use `DefaultLifecycleObserver` instead of deprecated `LifecycleObserver` with `@OnLifecycleEvent`
3. **Explicit lifecycle methods**: Override lifecycle methods directly (e.g., `override fun onStart()`) for better type safety
4. **Monitor deprecation warnings**: Address deprecations promptly to maintain compatibility with latest Android/Kotlin versions
5. **Test after migration**: Ensure deprecated API replacements maintain identical behavior

## Test Utilities

Test utilities are now module-specific and located in each module's test sources:

### Core Module Test Utils
**Location**: `sdk/core/src/androidTest/java/com/ibm/security/verifysdk/core/testutils/`
- `JsonExt.kt`: Provides configured `Json` instance for kotlinx.serialization with lenient parsing

### Authentication Module Test Utils
**Location**: `sdk/authentication/src/androidTest/java/com/ibm/security/verifysdk/authentication/testutils/`
- `JsonExt.kt`: JSON utilities for authentication tests
- `ApiMockEngine.kt`: Mock HTTP engine for OAuth/OIDC testing with request history tracking

### FIDO2 Module Test Utils
**Location**: `sdk/fido2/src/androidTest/java/com/ibm/security/verifysdk/fido2/testutils/`
- `JsonExt.kt`: JSON utilities for FIDO2 model serialization tests

**Benefits of Module-Specific Test Utils:**
- Better encapsulation - test utilities are co-located with tests
- No cross-module test dependencies
- Simpler project structure
- Each module is self-contained for testing
