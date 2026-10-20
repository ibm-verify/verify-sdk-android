plugins {
    id("sdk.android.library")
    id("sdk.publish")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.junit.ktx)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.rules)

    androidTestImplementation(libs.fuel.android)
}