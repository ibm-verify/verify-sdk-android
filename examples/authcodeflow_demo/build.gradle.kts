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

// Load config.properties at build time
val configPropertiesFile = file("src/main/assets/config.properties")
val configProperties = Properties()
if (configPropertiesFile.exists()) {
    configProperties.load(FileInputStream(configPropertiesFile))
} else {
    logger.lifecycle("config.properties not found, using default values.")
}

// Parse redirect URL to extract scheme, host, and path
val redirectUrl = configProperties.getProperty("redirect") ?: "https://sdk.verify.ibm.com/callback"
val redirectUri = URI(redirectUrl)
val redirectScheme = redirectUri.scheme ?: "https"
val redirectHost = redirectUri.host ?: "sdk.verify.ibm.com"
val redirectPath = redirectUri.path?.takeIf { it.isNotEmpty() } ?: "/callback"

android {
    namespace = "com.ibm.security.verifysdk.authcodeflow.demoapp"
    defaultConfig {
        applicationId = "com.ibm.security.verifysdk.authcodeflow.demoapp"

        // Use values from config.properties
        manifestPlaceholders["auth_redirect_scheme"] = redirectScheme
        manifestPlaceholders["auth_redirect_host"] = redirectHost
        manifestPlaceholders["auth_redirect_path"] = redirectPath
    }

    buildFeatures {
        compose = true
    }
}

dependencies {

    implementation(project(":sdk:authentication"))

    // Compose dependencies
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)

    androidTestImplementation(libs.androidx.espresso.core)
}