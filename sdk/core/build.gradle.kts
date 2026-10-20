plugins {
    id("sdk.android.library")
    id("sdk.ktor.client")
    id("sdk.publish")
    alias(libs.plugins.kotlin.serialization)
}

dependencies {

    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.core.ktx)
    implementation(libs.logging.interceptor)
    implementation(libs.appmattus.certificatetransparency)

    androidTestImplementation(libs.androidx.espresso.core)
}