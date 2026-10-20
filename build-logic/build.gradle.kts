plugins {
    `kotlin-dsl`
}

dependencies {
    // CVE-2026-110262 / CVE-2026-110270: asm-commons < 9.11 is pulled in transitively by AGP.
    // Constrain the whole ASM family to 9.11.1 for the build-logic classpath.
    constraints {
        listOf("asm", "asm-commons", "asm-tree", "asm-analysis", "asm-util").forEach {
            implementation("org.ow2.asm:$it:9.11.1") {
                because("CVE-2026-110262, CVE-2026-110270: asm-commons < 9.11")
            }
        }
    }

    implementation("com.android.tools.build:gradle:${libs.versions.agp.get()}")
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:${libs.versions.kotlin.get()}")
    implementation("org.jetbrains.dokka:dokka-gradle-plugin:${libs.versions.dokka.get()}")
}
