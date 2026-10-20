plugins {
    id("sdk.android.library")
    id("sdk.ktor.client")
    id("sdk.publish")
    alias(libs.plugins.kotlin.serialization)
}

android {
    defaultConfig {
        // for IBM Verify Authentication SDK
        manifestPlaceholders["auth_redirect_scheme"] = ""
        manifestPlaceholders["auth_redirect_host"] = ""
        manifestPlaceholders["auth_redirect_path"] = ""
    }
}

dependencies {

    api(project(":sdk:core"))
    api(project(":sdk:authentication"))

    implementation(libs.androidx.biometric)
    implementation(libs.androidx.core.ktx)
    implementation(libs.jackson.core)
    implementation(libs.jackson.dataformat.cbor)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.datetime)
    implementation(libs.rootbeer.lib)

    // Android instrumented test dependencies
    androidTestImplementation(kotlin("test"))
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.mockito.kotlin) {
        // Fix issue with byte-buddy and instrumentation tests
        exclude(group = "org.mockito", module = "mockito-core")
    }
}