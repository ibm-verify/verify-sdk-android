plugins {
    id("com.android.library")
}

val cleanModulePath = project.path.removePrefix(":sdk:").replace(":", ".")
val sdkNamespace = "com.ibm.security.verifysdk.$cleanModulePath"

android {
    namespace = sdkNamespace
    testNamespace = "$sdkNamespace.test"

    compileSdk = 37
    buildFeatures {
        buildConfig = true
    }

    val versionName = rootProject.extra.properties["versionName"] as? String ?: "3.2.13"

    defaultConfig {
        minSdk = 29
        buildConfigField("String", "VERSION_NAME", "\"$versionName\"")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        named("release") {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        named("debug") {
            enableUnitTestCoverage = true
            enableAndroidTestCoverage = true
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
            excludes += "META-INF/LICENSE.md"
            excludes += "META-INF/LICENSE-notice.md"
        }
        jniLibs {
            pickFirsts += "**/*.so"
        }
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

kotlin {
    jvmToolchain(17)
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

dependencies {
    "androidTestImplementation"(libs.findLibrary("androidx-junit").get())
    "androidTestImplementation"(libs.findLibrary("skyscreamer-jsonassert").get())
    "androidTestImplementation"(libs.findLibrary("slf4j-simple").get())
    "androidTestImplementation"(libs.findLibrary("slf4j-api").get())
    "lintChecks"(libs.findLibrary("compose-lint-checks").get())
    "lintChecks"(libs.findLibrary("slack-lint-checks").get())
    "lintChecks"(libs.findLibrary("lint-checks-android").get())
    "lintChecks"(libs.findLibrary("lint-checks").get())
    "testImplementation"(libs.findLibrary("junit").get())
}
