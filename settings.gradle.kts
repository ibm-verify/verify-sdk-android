// Root settings.gradle.kts
pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}


rootProject.name = "IBM Verify SDK"

include(":sdk:adaptive")
include(":sdk:authentication")
include(":sdk:core")
include(":sdk:fido2")
include(":sdk:mfa")
include(":sdk:test_utils")

include(":examples:authcodeflow_demo")
include(":examples:dpop_demo")
include(":examples:fido2_demo")
include(":examples:mfa_demo")

project(":examples:authcodeflow_demo").projectDir = File("examples/authcodeflow_demo")
project(":examples:dpop_demo").projectDir = File("examples/dpop_demo")
project(":examples:fido2_demo").projectDir = File("examples/fido2_demo")
project(":examples:mfa_demo").projectDir = File("examples/mfa_demo")
