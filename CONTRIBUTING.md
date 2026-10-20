# Contributing

Review the following guidelines for submitting questions, issues, or changes to this repository.

## Coding Style
This SDK follows coding style based on [Coding conventions﻿](https://kotlinlang.org/docs/coding-conventions.html/) for source code in the Kotlin Programming Language.

## Issues and Questions

If you encounter an issue, have a question or want to suggest an enhancement to the IBM Verify SDK, you are welcome to submit a [request](https://github.com/ibm-verify/verify-sdk-android/issues).
Before that, please search for similar issues. It's possible somebody has encountered this issue already.

## Pull Requests

If you want to contribute to the repository, here's a quick guide:

1. Fork the repository
2. Develop and test your code changes:
    * Follow the coding style as documented above
    * Please add one or more tests to validate your changes.
3. Make sure everything builds/tests cleanly.
4. Commit your changes
5. Push to your fork and submit a pull request to the `main` branch


## Building the project

The project uses Gradle with the Kotlin DSL and requires JDK 17. Run all Gradle commands from the repository root using the included wrapper:

```
./gradlew assemble                       # build all modules
./gradlew :sdk:core:assembleDebug        # build a single module
./gradlew testSdk                        # JVM unit tests of all :sdk:* modules
./gradlew connectedAndroidTestSdk        # instrumented tests of all :sdk:* modules (device/emulator required)
```

### Build logic

Shared build configuration is provided by convention plugins in the [`build-logic`](build-logic) included build (registered in `settings.gradle.kts` via `pluginManagement { includeBuild("build-logic") }`). It replaces the former `common-config*.gradle` and `common-publish.gradle` scripts.

| Plugin id | Used by | Purpose |
|---|---|---|
| `sdk.android.library` | `sdk/*` | Android library defaults: namespace, SDK levels, build types, packaging, Java/Kotlin 17 toolchain, lint checks and common test dependencies |
| `sdk.ktor.client` | `sdk/core`, `sdk/authentication`, `sdk/mfa`, `sdk/fido2`, demos | Ktor client dependencies |
| `sdk.publish` | `sdk/*` | `maven-publish` setup, sources/javadoc JARs and POM metadata |
| `sdk.android.demo` | `examples/*` | Android application defaults for the demo apps |

A module build file only applies the plugins it needs by id, for example `id("sdk.android.library")`, and adds module-specific settings and dependencies. To change a setting that applies to several modules, edit the matching plugin in `build-logic/src/main/kotlin/`. Dependency versions are managed in `gradle/libs.versions.toml`, and the SDK release version is set in the root `build.gradle.kts` (`extra["versionName"]`).

## Generating documentation

To generate the HTML docs for all SDK components, run `./gradlew dokkaGeneratePublicationHtml` from the repository root. View the docs of a component in its `sdk/<component>/build/dokka/html` directory:

```
open sdk/<component>/build/dokka/html/index.html
```


## Additional Resources

* [General GitHub documentation](https://help.github.com/)
* [GitHub pull request documentation](https://help.github.com/send-pull-requests/)


# Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
   have the right to submit it under the open source license
   indicated in the file; or

(b) The contribution is based upon previous work that, to the best
   of my knowledge, is covered under an appropriate open source
   license and I have the right under that license to submit that
   work with modifications, whether created in whole or in part
   by me, under the same open source license (unless I am
   permitted to submit under a different license), as indicated
   in the file; or

(c) The contribution was provided directly to me by some other
   person who certified (a), (b) or (c) and I have not modified
   it.

(d) I understand and agree that this project and the contribution
   are public and that a record of the contribution (including all
   personal information I submit with it, including my sign-off) is
   maintained indefinitely and may be redistributed consistent with
   this project or the open source license(s) involved.
