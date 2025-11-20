# IBM Verify SDK for Android

This repository is for active development of the IBM Verify Software Development Kit for Android.

## Getting started

Each Software Development Kit (SDK) is separate for you to choose from instead of one large IBM Verify SDK package. To get started with a specific SDK, see the README.md file located in the specific project folder.

## Prerequisites

* The SDK is written in Kotlin.
* To use the `dc` or `mfa` SDK an [IBM Verify](https://www.ibm.com/products/verify-for-consumer-iam) tenant or [IBM Verify Identity Access](https://www.ibm.com/au-en/products/verify-access) is required.

## Software Development Kits

The following SDKs are currently offered in the package:

| Component | Description |
| ----------- | ----------- |
| [FIDO2](sdk/fido2) | The FIDO2™ component is a native implementation of attestation and assertion ceremonies.  Essentially providing the equivalent of WebAuthn's `navigator.credentials.create()` and `navigator.credentials.get()` for native mobile apps.|
| [Adaptive](sdk/adaptive) | The IBM Verify Adaptive SDK provides device assessment. Based on cloud risk policies, authentication and authorization challenges can be evaluated.|
| [Core](sdk/core) | The IBM Verify Core SDK provides common Keychain and networking functionality across the other components in the IBM Verify SDK offering.|
| [Authentication](sdk/authentication) | The IBM Verify Authentication SDK is an implementation of OAuth 2.0 and OIDC targeting mobile use cases.|
| [MFA](sdk/mfa) | The IBM Verify MFA SDK provides multi-factor authentication support for creating authenticators and processing transactions.|
| [DC](sdk/dc) | The IBM Verify DC SDK supporting digital credentials in a mobile device Wallet.|

## Integrating with your project

To include an IBM Verify SDK modules in your Android project, follow these steps:

1. Add JitPack to your repositories

   In your root-level `settings.gradle.kts` add the JitPack repository:

    ```kotlin
	dependencyResolutionManagement {
		repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
		repositories {
			// other repositories
			maven { url = uri("https://jitpack.io") }
		}
	}
    ```

2. Add the SDK dependencies

   In your app-level `build.gradle.kts` add the SDK modules you want to use:

    ```kotlin
    dependencies {
        implementation("com.github.ibm-verify.verify-sdk-android:verify-sdk-authentication:3.0.9")
        implementation("com.github.ibm-verify.verify-sdk-android:verify-sdk-<module>:<version>)
        ...
    }
    ```

   Replace `version` with `main-SNAPSHOT` for the latest development snapshot. You can generate entries for other modules [here](https://jitpack.io/#ibm-verify/verify-sdk-android/).

3. Sync and build

   After adding the dependency, sync your project with Gradle files and build your app.

### Manually from GitHub release

Download the required SDK files from https://github.com/ibm-verify/verify-sdk-android/releases/latest,  store them into the lib folder and sync your project.