plugins {
    id("com.android.application")
}

android {
    compileSdk = 37

    defaultConfig {
        minSdk = 29
        targetSdk = 36
        versionCode = 11
        versionName = "1.3.5"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}

kotlin {
    jvmToolchain(17)
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

dependencies {
    "implementation"(libs.findLibrary("slf4j-simple").get())
    "implementation"(libs.findLibrary("androidx-activity-compose").get())
    "implementation"(libs.findLibrary("androidx-appcompat").get())
    "implementation"(libs.findLibrary("androidx-compose-material-icons-extended").get())
    "implementation"(libs.findLibrary("androidx-core-ktx").get())
    "implementation"(libs.findLibrary("androidx-lifecycle-runtime-ktx").get())
    "implementation"(libs.findLibrary("androidx-navigation-compose").get())
    "implementation"(libs.findLibrary("google-material").get())
    "implementation"(libs.findLibrary("kotlinx-serialization-json").get())
    "implementation"(libs.findLibrary("materialx").get())

    "testImplementation"(libs.findLibrary("junit").get())
    "androidTestImplementation"(libs.findLibrary("androidx-junit").get())
}
