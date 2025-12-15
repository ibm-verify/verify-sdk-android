// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.jetbrains.kotlin.android) apply false
    alias(libs.plugins.jetbrains.kotlin.jvm) apply false
    alias(libs.plugins.jetbrains.dokka)
    java
    jacoco
    alias(libs.plugins.neotech.rootcoverage) apply true
    alias(libs.plugins.kotlin.kapt) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.jetbrains.compose) apply false
    alias(libs.plugins.compose.compiler) apply false
}

// used for release naming and in MFA SDK
extra["versionName"] = "3.0.11"
extra["versionCode"] = "112"

dependencies {
    add("implementation", enforcedPlatform("com.fasterxml.jackson:jackson-bom:2.15.3"))
}

allprojects {
    configurations.configureEach {
        resolutionStrategy {
            failOnVersionConflict()
            preferProjectModules()
            // Force versions not covered by BOM
            force("com.fasterxml.woodstox:woodstox-core:6.6.2")
            force("com.google.guava:guava:32.0.1-jre")
            force("com.google.protobuf:protobuf-java:3.25.5")
            force("com.google.protobuf:protobuf-javalite:3.25.5")
            force("commons-io:commons-io:2.14.0")
            force("io.netty:netty-codec-http2:4.2.5.Final")
            force("io.netty:netty-codec-compression:4.2.5.Final")
            force("io.netty:netty-handler-proxy:4.2.5.Final")
        }
    }

    val jacksonModules = listOf(
        "com.fasterxml.jackson.core:jackson-core:2.15.3",
        "com.fasterxml.jackson.core:jackson-databind:2.15.3",
        "com.fasterxml.jackson.core:jackson-annotations:2.15.3",
        "com.fasterxml.jackson.module:jackson-module-kotlin:2.15.3",
        "com.fasterxml.jackson.dataformat:jackson-dataformat-xml:2.15.3",
        "com.fasterxml.jackson.module:jackson-module-jaxb-annotations:2.15.3"
    )

    configurations.matching { it.name.contains("dokka", ignoreCase = true) }.all {
        resolutionStrategy {
            jacksonModules.forEach { force(it) }
        }
    }
}

rootCoverage {
    excludes = listOf(
        "**/R.class",
        "**/R\$*.class",
        "**/*Companion*.class",
        "**/*Function0*.class",
        "**/BuildConfig.*",
        "**/Manifest*.*",
        "**/*Test*.*",
        "android/**/*.*",
        "**/*\$Lambda$*.*",  // Jacoco can't handle several "$" in class names.
        "**/*\$inlined$*.*"  // Kotlin specific classes Jacoco can't handle.
    )

    generateHtml = true
    generateXml = true
}

tasks.jacocoTestCoverageVerification {
    violationRules {
        rule {
            limit {
                counter = "BRANCH"
                value = "COVEREDRATIO"
                minimum = "0.50".toBigDecimal() // Adjust the threshold for branch coverage
            }
        }
    }
}

subprojects {
    apply {
        plugin("maven-publish")
        plugin("org.jetbrains.dokka")
    }

    /**
     * List all first-level dependencies for a specific module.
     */
    tasks.register("listFirstLevelDependencies") {
        doLast {
            configurations["releaseCompileClasspath"]
                .resolvedConfiguration
                .firstLevelModuleDependencies
                .forEach { dependency ->
                    println("${dependency.moduleGroup}:${dependency.moduleName}:${dependency.moduleVersion}")
                }
        }
    }

    /**
     * List all dependencies for a specific module.
     */
    tasks.register<DependencyReportTask>("allDeps")
}

/**
 * Inspect the dependencies of all leaf projects and reports any dependencies that belong to a
 * specific module (starting with modulePrefixFilter value).
 *
 * Helps detect if certain modules pull in older or unexpected versions of libraries, which is
 * exactly what happens with Mend scans.
 *
 * Example output:
 *      Project :sdk:mfa
 *          Config: :sdk:mfa:debugAndroidTestCompileClasspath
 *              -->  com.fasterxml.jackson.core:jackson-core:2.15.3
 *               -->  com.fasterxml.jackson:jackson-bom:2.15.3
 *
 */
tasks.register("inspectLibDependencies") {

    val modulePrefixFilter = "com.fasterxml.jackson"

    doLast {
        val leafProjects = rootProject.allprojects.filter {
            it.subprojects.isEmpty() && it.path !in listOf(
                ":examples",
                ":sdk"
            )
        }

        leafProjects.forEach { p ->
            println("Project ${p.path}")

            val configs = p.configurations.filter { it.isCanBeResolved }

            configs.forEach { config ->
                try {
                    val result = config.incoming.resolutionResult.allDependencies
                        .filterIsInstance<ResolvedDependencyResult>()
                        .map { it.selected }
                        .filter { it.moduleVersion?.group?.startsWith(modulePrefixFilter) == true }

                    if (result.isNotEmpty()) {
                        println("  Config: ${p.path}:${config.name}")
                        result.forEach { dep ->
                            println("    -->  ${dep.moduleVersion?.group}:${dep.moduleVersion?.name}:${dep.moduleVersion?.version}")
                        }
                    }
                } catch (e: Exception) {
                    println("    *** Could not resolve ${config.name}: ${e.message}")
                }
            }
        }
    }
}
