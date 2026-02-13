plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    id("kotlin-parcelize")
}

apply(from = "$rootDir/common-config.gradle")
apply(from = "$rootDir/common-config-ktor.gradle")
apply(from = "$rootDir/common-publish.gradle")

dependencies {

    api(project(":sdk:core"))

    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.browser)
    implementation(libs.androidx.core.ktx)
    implementation(libs.google.material)
    implementation(libs.jose4j)
    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.logging.interceptor)

    androidTestImplementation(project(":sdk:test_utils"))
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.mockito.kotlin) {
        // Fix issue with byte-buddy and instrumentation tests
        exclude(group = "org.mockito", module = "mockito-core")
    }
    androidTestImplementation(libs.kotlinx.coroutines.test)
}