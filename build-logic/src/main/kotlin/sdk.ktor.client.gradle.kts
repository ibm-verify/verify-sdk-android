val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

dependencies {
    "implementation"(libs.findLibrary("ktor-client-android").get())
    "implementation"(libs.findLibrary("ktor-client-auth").get())
    "implementation"(libs.findLibrary("ktor-client-cio").get())
    "implementation"(libs.findLibrary("ktor-client-content-negotiation").get())
    "implementation"(libs.findLibrary("ktor-client-core").get())
    "implementation"(libs.findLibrary("ktor-client-logging").get())
    "implementation"(libs.findLibrary("ktor-client-okhttp").get())
    "implementation"(libs.findLibrary("ktor-client-serialization").get())
    "implementation"(libs.findLibrary("ktor-serialization-kotlinx-json").get())
    "androidTestImplementation"(libs.findLibrary("ktor-client-mock").get())
}
