plugins {
    id("sdk.android.demo")
    id("sdk.ktor.client")
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.ibm.security.verifysdk.fido2.demoapp"
    defaultConfig {
        applicationId = "com.ibm.security.verifysdk.fido2.demoapp"
    }
}

dependencies {

    implementation(project(":sdk:fido2"))

    implementation(libs.androidx.biometric)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.logging.interceptor)

    androidTestImplementation(libs.androidx.espresso.core)
}