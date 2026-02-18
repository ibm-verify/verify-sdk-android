/*
 * Copyright contributors to the IBM Verify SDK for Android project
 */

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
}

apply(from = "$rootDir/common-config.gradle")
apply(from = "$rootDir/common-config-ktor.gradle")

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.junit.ktx)
    implementation(libs.kotlinx.coroutines.test)
    implementation(libs.ktor.client.mock)
    implementation(libs.logging.interceptor)
    androidTestImplementation(libs.mockito.kotlin) {
        // Fix issue with byte-buddy and instrumentation tests
        exclude(group = "org.mockito", module = "mockito-core")
    }
}