plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
    alias(libs.plugins.compose.compiler)
}

apply(from = "$rootDir/common-config-demos.gradle")
apply(from = "$rootDir/common-config-ktor.gradle")

android {
    namespace = "com.ibm.security.verifysdk.dc.demoapp"
    defaultConfig {
        applicationId = "com.ibm.security.verifysdk.dc.demoapp"

        manifestPlaceholders["auth_redirect_scheme"] = ""
        manifestPlaceholders["auth_redirect_host"] = ""
        manifestPlaceholders["auth_redirect_path"] = ""
    }

    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = libs.versions.compose.compiler.get()
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {

    implementation(project(":sdk:dc"))

    implementation(libs.androidx.material3)
    implementation(libs.androidx.material3.adaptive.core)
    implementation(libs.androidx.material3.adaptive.layout)
    implementation(libs.androidx.material3.adaptive.navigation)
    implementation(libs.androidx.room.ktx)
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.zxing.android.embedded)
    implementation(platform(libs.androidx.compose.bom))
    implementation("androidx.compose.material:material-icons-extended")

    annotationProcessor(libs.androidx.room.compiler)

    ksp(libs.androidx.room.compiler)

    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.ui.test.junit4)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    debugImplementation(libs.androidx.ui.test.manifest)
    debugImplementation(libs.androidx.ui.tooling)
}
