plugins {
    id("sdk.android.library")
    id("sdk.ktor.client")
    id("sdk.publish")
    alias(libs.plugins.kotlin.serialization)
    id("kotlin-parcelize")
}

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

    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.robolectric)

    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.mockito.kotlin) {
        // Fix issue with byte-buddy and instrumentation tests
        exclude(group = "org.mockito", module = "mockito-core")
    }
    androidTestImplementation(libs.kotlinx.coroutines.test)
}