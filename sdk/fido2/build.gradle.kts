plugins {
    id("sdk.android.library")
    id("sdk.ktor.client")
    id("sdk.publish")
    alias(libs.plugins.kotlin.serialization)
}

dependencies {

    api(project(":sdk:core"))

    implementation(libs.androidx.biometric)
    implementation(libs.androidx.core.ktx)
    implementation(libs.jackson.core)
    implementation(libs.jackson.dataformat.cbor)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.datetime)

    androidTestImplementation(project(":sdk:core"))
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.mockito.kotlin) {
        // Fix issue with byte-buddy and instrumentation tests
        exclude(group = "org.mockito", module = "mockito-core")
    }
    androidTestImplementation(libs.kotlinx.coroutines.test)
}
