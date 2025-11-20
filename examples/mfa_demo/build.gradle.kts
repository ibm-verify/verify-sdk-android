plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.compose.compiler)
}

apply(from = "$rootDir/common-config-demos.gradle")
apply(from = "$rootDir/common-config-ktor.gradle")

android {
    namespace = "com.ibm.security.verifysdk.mfa.demoapp"
    defaultConfig {
        applicationId = "com.ibm.security.verifysdk.mfa.demoapp"

        manifestPlaceholders["auth_redirect_scheme"] = "verifysdk"
        manifestPlaceholders["auth_redirect_host"] = "callback"
        manifestPlaceholders["auth_redirect_path"] = "/redirect"
    }
    
    buildFeatures {
        compose = true
    }
}

dependencies {

    implementation(project(":sdk:mfa"))

    implementation(libs.zxing.android.embedded)
    implementation(libs.androidx.biometric)
    
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