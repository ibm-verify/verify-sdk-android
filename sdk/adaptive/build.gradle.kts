plugins {
    alias(libs.plugins.android.library)
}

apply(from = "$rootDir/common-config.gradle")
apply(from = "$rootDir/common-publish.gradle")

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.junit.ktx)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.rules)

    androidTestImplementation(libs.fuel.android)
}