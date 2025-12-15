import java.io.FileInputStream
import java.util.Properties

import java.net.URI

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.compose.compiler)
}

apply(from = "$rootDir/common-config-demos.gradle")
apply(from = "$rootDir/common-config-ktor.gradle")

val configPropertiesFile = file("src/main/assets/config.properties")
val configProperties = Properties()
if (configPropertiesFile.exists()) {
    configProperties.load(FileInputStream(configPropertiesFile))
    logger.lifecycle("config.properties loaded, using custom values.")
} else {
    logger.lifecycle("config.properties not found, using default values.")
}

val redirectUrl = configProperties.getProperty("redirect") ?: ""
val redirectUri = URI(redirectUrl)
val redirectScheme = redirectUri.scheme ?: "https"
val redirectHost = redirectUri.host ?: "sdk.verify.ibm.com"
val redirectPath = redirectUri.path?.takeIf { it.isNotEmpty() } ?: "/callback"

android {
    namespace = "com.ibm.security.verifysdk.authcodeflow.demoapp"
    defaultConfig {
        applicationId = "com.ibm.security.verifysdk.authcodeflow.demoapp"

        /**
         * Configure manifest placeholders for deep link handling.
         *
         * These placeholders are used in AndroidManifest.xml to configure the intent-filter
         * for the AuthenticationActivity, enabling the app to handle OAuth redirect callbacks.
         */
        manifestPlaceholders["auth_redirect_scheme"] = redirectScheme
        manifestPlaceholders["auth_redirect_host"] = redirectHost
        manifestPlaceholders["auth_redirect_path"] = redirectPath
    }

    buildFeatures {
        compose = true
    }
}

/**
 * Custom Gradle task to verify the merged Android manifest.
 *
 * This task:
 * 1. Depends on the processDebugManifest task to ensure the manifest is generated
 * 2. Reads the merged manifest file from the build intermediates directory
 * 3. Extracts and prints lines 45-65 which should contain the intent-filter configuration
 * 4. Verifies that the AuthenticationActivity is present in the manifest
 *
 * This verification helps ensure that the OAuth redirect deep link handling is
 * properly configured in the final manifest.
 */
tasks.register("verifyMergedManifest") {
    dependsOn("processDebugManifest")

    doLast {
        println("====================================================================")
        println("======= Show intent-filter section for verification purposes =======")
        val path = "${layout.buildDirectory.get()}/intermediates/merged_manifest/debug/processDebugMainManifest/AndroidManifest.xml"
        println("======= Manifest file: $path =======")

        val manifestFile = file(
            path
        )

        require(manifestFile.exists()) {
            "Merged manifest not found"
        }

        val lines = manifestFile.readLines()
        val from = 45
        val to = 65
        val slice = lines.subList(from, minOf(to, lines.size))

        println("======= Manifest lines ${from}–${to} =======")
        slice.forEach { println(it) }

        if (slice.none { it.contains("AuthenticationActivity") }) {
            error("Expected AuthenticationActivity not found")
        }
        println("====================================================================")

    }
}

/**
 * Configure the assemble task to run manifest verification after completion.
 *
 * This ensures that every build verifies the manifest configuration is correct.
 */
tasks.named("assemble") {
    finalizedBy("verifyMergedManifest")
}

dependencies {

    // IBM Verify SDK authentication module
    implementation(project(":sdk:authentication"))

    // SLF4J Simple logger for SLF4J 2.x (outputs to System.err which Android redirects to Logcat)
    implementation(libs.slf4j.simple)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)

    androidTestImplementation(libs.androidx.espresso.core)
}