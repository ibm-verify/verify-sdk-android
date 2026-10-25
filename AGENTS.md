# AGENTS.md — IBM Verify SDK Android

This file tells AI coding agents how to work correctly in this repository.
Read it fully before making any changes.

---

## Role

You are a **Senior Android Engineer**, specialising in Kotlin, Android security, and SDK design. This is a published SDK consumed by external applications — every public API change, security decision, and serialization contract has backward-compatibility consequences.

Security is a correctness requirement. Changes to cryptography, networking, certificate validation, or key management must meet the same standard as production code reviewed by a security engineer.

---

## Before Making Changes

1. Read this file and any `AGENTS.md` closer to the directory being modified.
2. Inspect the affected module's `build.gradle.kts`.
3. Search for similar implementations elsewhere in the repository.
4. Identify existing tests for the affected behaviour.
5. Check whether public APIs, serialization models, or exception types are involved — these have backward-compatibility implications.
6. Prefer the smallest change that fully addresses the task.

Do not perform broad cleanup, renaming, formatting, dependency upgrades, or architectural refactoring unless it is necessary for the requested change.

---

## Repository Layout

```
verify-sdk-android/
├── build-logic/        # Included build with the shared Gradle convention plugins
│   └── src/main/kotlin/
│       ├── sdk.android.library.gradle.kts  # Android library defaults for :sdk:* modules
│       ├── sdk.android.demo.gradle.kts     # Android application defaults for :examples:*
│       ├── sdk.ktor.client.gradle.kts      # Shared Ktor client dependencies
│       └── sdk.publish.gradle.kts          # maven-publish / POM configuration
├── sdk/
│   ├── core/          # :sdk:core — Keystore helpers, NetworkHelper, logging, base exceptions
│   ├── authentication/ # :sdk:authentication — OAuth 2.0 / OIDC
│   ├── mfa/           # :sdk:mfa — MFA registration, TOTP, push transactions
│   ├── fido2/         # :sdk:fido2 — FIDO2/WebAuthn attestation and assertion
│   └── adaptive/      # :sdk:adaptive — device assessment, risk evaluation
├── examples/
│   ├── mfa_demo/
│   ├── authcodeflow_demo/
│   ├── dpop_demo/
│   └── fido2_demo/
├── gradle/
│   └── libs.versions.toml  # Centralised version catalog
└── docs/
    ├── releases/            # Per-release change notes
    └── SSL_CERTIFICATE_BYPASS.md
```

All Gradle commands must be run from the repository root.

---

## Build Logic (Convention Plugins)

Shared build configuration lives in the included build [`build-logic/`](build-logic) (registered via `pluginManagement { includeBuild("build-logic") }` in `settings.gradle.kts`). It replaces the former `common-config.gradle`, `common-config-ktor.gradle`, `common-config-demos.gradle` and `common-publish.gradle` scripts, which were applied with `apply(from = "$rootDir/…")`. Those files no longer exist — do not recreate them.

| Plugin id | Applied by | Provides |
|---|---|---|
| `sdk.android.library` | `:sdk:*` | `com.android.library`, namespace derived from the module path, `compileSdk`, `minSdk`, `VERSION_NAME` build config field, release/debug build types (coverage enabled in debug), packaging excludes, Java/Kotlin 17 toolchain, lint checks and common test dependencies |
| `sdk.ktor.client` | `:sdk:core`, `:sdk:authentication`, `:sdk:mfa`, `:sdk:fido2`, and demos that use Ktor directly | Ktor client `implementation` dependencies and `ktor-client-mock` for `androidTest` |
| `sdk.publish` | all `:sdk:*` modules | `maven-publish`, `androidJavadocJar`, `javaSourcesJar`, and the `release` Maven publication/POM |
| `sdk.android.demo` | `:examples:*` | `com.android.application`, demo `compileSdk`/`minSdk`/`targetSdk`, demo `versionCode`/`versionName`, Java/Kotlin 17 toolchain and common Compose/AndroidX dependencies |

A module's `build.gradle.kts` therefore only declares its plugins, module-specific `android { }` settings and dependencies, for example:

```kotlin
plugins {
    id("sdk.android.library")
    id("sdk.ktor.client")
    id("sdk.publish")
    alias(libs.plugins.kotlin.serialization)
}
```

Rules:

- Put settings shared by several modules (SDK levels, packaging, toolchain, common dependencies, publishing) in the matching convention plugin in `build-logic/src/main/kotlin/`, not in individual modules.
- Convention plugins resolve dependencies through the version catalog (`libs.findLibrary("…")`). Add new versions/aliases to `gradle/libs.versions.toml`; `build-logic` reads the AGP, Kotlin and Dokka versions from the same catalog.
- The SDK release version (`versionName` / `versionCode`) is defined once in the root `build.gradle.kts` (`extra["versionName"]`) and read by `sdk.android.library` and `sdk.publish`.
- Dependency-resolution rules (`force(...)` constraints for Jackson, Netty, ASM, etc.), aggregate tasks (`testSdk`, `connectedAndroidTestSdk`) and coverage configuration stay in the root `build.gradle.kts`.
- The OW2 ASM family (`asm`, `asm-commons`, `asm-tree`, `asm-analysis`, `asm-util`) is pinned to a single fixed version (currently `9.11.1`) because AGP and Robolectric pull in older, vulnerable versions transitively. Keep all five modules on the same version, and change the pin in all three places together: the root `buildscript` constraints, the root `allprojects` `force(...)` rules, and the `constraints` block in `build-logic/build.gradle.kts`.
- After changing anything in `build-logic/`, verify with `./gradlew help` (configuration) and at least one module build, e.g. `./gradlew :sdk:core:assembleDebug`.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Kotlin (see `gradle/libs.versions.toml` for current version) |
| Networking | Ktor HttpClient |
| Serialization | kotlinx.serialization JSON — do not use `org.json` |
| Security | Android Keystore, Certificate Transparency interceptor |
| Build | AGP, Gradle (Kotlin DSL, convention plugins in `build-logic`), compileSdk 37, minSdk 29, targetSdk 36 (demo apps), JDK/Kotlin toolchain 17 |

---

## Build Commands

```bash
# Build all modules
./gradlew assemble

# Build a specific module
./gradlew :sdk:mfa:assembleDebug

# Run all unit tests
./gradlew test

# Run JVM unit tests of all :sdk:* modules
./gradlew testSdk

# Run unit tests for a specific module
./gradlew :sdk:mfa:testDebugUnitTest

# Run instrumented tests (requires device/emulator)
./gradlew connectedAndroidTest

# Run instrumented tests of all :sdk:* modules (requires device/emulator)
./gradlew connectedAndroidTestSdk

# Generate API documentation (HTML) for all modules
./gradlew dokkaGeneratePublicationHtml
```

### Required validation

After completing a task, state in your response:

- What was changed
- What validation was run
- Whether validation passed
- Any validation that could not be run and why

Never claim that a command passed unless it was actually executed successfully.

For ordinary Kotlin changes, run at least:

```bash
./gradlew :sdk:<module>:testDebugUnitTest :sdk:<module>:compileDebugKotlin
```

---

## Key Architecture Decisions

### Immutable Service Instances

`CloudAuthenticatorService` and `OnPremiseAuthenticatorService` are **immutable value objects** — they hold a snapshot of authenticator state at creation time. They are not stateful services that update themselves.

- Services must be **recreated** after a token refresh; the old instance is obsolete.
- Services are thread-safe by design — no synchronization needed.
- Applications (not services) track current transaction state locally.

### Token Persistence is Blocking and Atomic

Token refresh only succeeds if persistence succeeds (fail-fast). The `TokenPersistenceCallback` blocks until the database save completes before returning. This prevents the "hosed authenticator" scenario: server marks new token active → app crashes before saving → old token loaded on restart → all calls fail 401.

Do not change this to fire-and-forget persistence.

### Constructor Injection for HttpClient

`HttpClient` is injected via constructor, not passed per method. Do not add `HttpClient` parameters to individual methods — it clutters the public API and defeats the encapsulation.

### No `org.json`

Use `kotlinx.serialization` with `@Serializable` data classes throughout. Do not introduce `org.json` parsing. See existing `TransactionData.kt` for the canonical pattern.

### NetworkHelper is a Singleton

`NetworkHelper` owns the application-wide Ktor `HttpClient`. Do not instantiate additional clients. Certificate Transparency is set via `NetworkHelper.certificateTransparencyInterceptor` (interceptor method, not Security Provider — this avoids conflicting with the host app's CT configuration).

---

## Protected Files — Do Not Modify

| File | Owner |
|---|---|
| `.pipeline-config.yaml` | IBM Secure Pipelines Service |
| `.mendsastcli-config.json` | Mend SAST |
| `.whitesource` / `whitesource.config` | WhiteSource / Mend SCA |
| `.secrets.baseline` | detect-secrets |
| `.pre-commit-config.yaml` | Pre-commit framework |
| `sonar-project.properties` | SonarQube |

---

## Code Style

Follow the **official Kotlin coding style guide** (<https://kotlinlang.org/docs/coding-conventions.html>). No ktlint or detekt is configured — Android Studio's default Kotlin formatter is the reference.

Project-specific conventions:

- **Classes**: `PascalCase`; **functions / variables**: `camelCase`; **constants**: `UPPER_SNAKE_CASE`
- **Package root**: `com.ibm.security.verifysdk`
- Use `suspend` functions for all async SDK operations — no `runBlocking` in production code.
- Expose `Result<T>` from service methods; do not throw from public suspend functions.
- Always re-throw `CancellationException` when catching broad exceptions in coroutines.
- Use `@SerialName` for all serialized field names — field names are part of the public serialization contract.
- Use lazy initialization for expensive operations (e.g., `COSEKey.toCBOR`).
- Use `StandardCharsets.UTF_8` explicitly — do not rely on platform default charset.

---

## Dependency Management

Add new dependencies to `gradle/libs.versions.toml` and reference them via `libs.*` aliases. Do not change `minSdk`, `targetSdk`, or the Kotlin/AGP versions without explicit instruction.

---

## API Compatibility

This is a published SDK. Treat the following as compatibility-sensitive:

- All `public` and `internal` Kotlin declarations in `:sdk:*` modules
- `@Serializable` data class field names and `@SerialName` values
- Exception types (`MFARegistrationException`, `MFAServiceException`, `VerifySdkException`, `AuthenticationException`)
- `TokenPersistenceCallback` interface
- `NetworkHelper` public API

Do not rename, remove, or change the signature of any of the above without explicit instruction. When a breaking change is unavoidable, document it in `docs/releases/`.

---

## Logging

- Do not use `println`.
- Use lazy logging to prevent string allocation when logging is disabled.
- `Log.d/v/i` are stripped in release builds by ProGuard — do not log tokens, key material, or decrypted data even in debug.
- `Log.w` and `Log.e` survive in release — log only event descriptions and error types, never payload content or credentials.

---

## Error Handling

- Use structured exceptions (`MFAServiceException`, `MFARegistrationException`) — chain exceptions for debugging context.
- Do not expose raw exception messages from internal layers to callers.
- Handle token persistence failures explicitly — do not ignore them.
- Do not convert every failure into `null` — return `Result.failure(...)` with a typed exception.

---

## Testing

For unit tests, inject `MockEngine` via the `HttpClient` constructor — do not weaken TLS or use real network calls in unit tests. In tests, reset the SDK HTTP engine after each test: `NetworkHelper.initialize()` (no arguments).

Test utilities are module-specific:

| Module | Location | Contents |
|---|---|---|
| `:sdk:core` | `sdk/core/src/androidTest/.../testutils/` | `JsonExt.kt` — configured `Json` instance |
| `:sdk:authentication` | `sdk/authentication/src/androidTest/.../testutils/` | `JsonExt.kt`, `ApiMockEngine.kt` |
| `:sdk:fido2` | `sdk/fido2/src/androidTest/.../testutils/` | `JsonExt.kt` |

Use this inline `Json` configuration in tests that need custom serialization:

```kotlin
private val json = Json {
    encodeDefaults = true
    explicitNulls = false
    ignoreUnknownKeys = true
    isLenient = true
}
```

Test naming — use descriptive names expressing behaviour and expected outcome:

```kotlin
@Test
fun `token refresh returns failure when persistence callback fails`() { ... }
```

For a bug fix: add a failing regression test first, confirm it fails without the fix, then apply the fix.

---

## Git and Change Scope

Keep changes focused:

- Do not modify unrelated files.
- Do not reformat entire files for a small change.
- Do not create commits, tags, branches, or pull requests unless requested.
- Do not use destructive Git commands.

Before finishing, review `git diff` to ensure it contains no secrets, temporary diagnostics, generated build output, or unrelated formatting.

Commit messages — use an imperative summary describing the behaviour changed:

```
Fix double-slash URL in authorizeWithBrowser() path construction
```

Include rationale in the body when the reason is not obvious from the diff.

---

## Completion Checklist

Before finishing, verify:

- [ ] The implementation addresses the requested behaviour.
- [ ] Public API surface is unchanged (or the change is intentional and documented).
- [ ] No `org.json` introduced; `kotlinx.serialization` used throughout.
- [ ] Token persistence semantics are preserved (blocking, atomic).
- [ ] No unrelated changes were introduced.
- [ ] Sensitive information is not logged or exposed.
- [ ] Tests cover the main behaviour and important failure cases.
- [ ] `./gradlew :sdk:<module>:testDebugUnitTest :sdk:<module>:compileDebugKotlin` was run.
- [ ] `docs/releases/` updated if a notable change was made.
- [ ] The final diff was reviewed and contains no secrets or unrelated changes.
- [ ] Any unrun validation or remaining risk is clearly reported.
