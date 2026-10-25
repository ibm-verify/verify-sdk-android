plugins {
    `maven-publish`
}

val androidExtension = extensions.findByType<com.android.build.api.dsl.LibraryExtension>()

tasks.register<Jar>("androidJavadocJar") {
    val dokkaTask = tasks.findByName("dokkaGeneratePublicationHtml")
    if (dokkaTask != null) {
        dependsOn(dokkaTask)
    }
    archiveClassifier.set("javadoc")
    from(layout.buildDirectory.dir("dokka/html"))
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

tasks.register<Jar>("javaSourcesJar") {
    archiveClassifier.set("sources")
    if (androidExtension != null) {
        from(androidExtension.sourceSets.getByName("main").java.directories)
    }
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

afterEvaluate {
    val releaseVersionName = rootProject.extra.properties["versionName"] as? String ?: "3.2.13"
    configure<PublishingExtension> {
        publications {
            register<MavenPublication>("release") {
                val releaseComponent = components.findByName("release")
                if (releaseComponent != null) {
                    from(releaseComponent)
                }
                artifactId = "verify${project.path.replace(":", "-")}"
                groupId = "com.github.ibm-verify"
                version = releaseVersionName
                pom {
                    name.set(artifactId)
                    description.set("IBM Verify ${project.name.uppercase()} SDK for Android")
                    url.set("https://github.com/ibm-verify/verify-sdk-android")
                    licenses {
                        license {
                            name.set("MIT License")
                            url.set("https://github.com/ibm-verify/verify-sdk-android/blob/main/LICENSE")
                        }
                    }
                    scm {
                        connection.set("scm:git:git://github.com/ibm-verify/verify-sdk-android.git")
                        developerConnection.set("scm:git:ssh://github.com/ibm-verify/verify-sdk-android.git")
                        url.set("https://github.com/ibm-verify/verify-sdk-android")
                    }
                    developers {
                        developer {
                            id.set("ibm-verify")
                            name.set("IBM Verify")
                            email.set("verify@au1.ibm.com")
                        }
                    }
                }
            }
        }
    }
}
