plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.serialization)
}

apply(from = "$rootDir/common-config-demos.gradle")
apply(from = "$rootDir/common-config-ktor.gradle")

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

    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}