plugins {
    alias(libs.plugins.binary.compatibility.validator)
    alias(libs.plugins.dokka)
}

group = "dev.webauthn"
version = "0.1.0-SNAPSHOT"

allprojects {
    group = rootProject.group
    version = rootProject.version

    repositories {
        mavenCentral()
        google()
    }

    dependencyLocking {
        lockAllConfigurations()
    }
}

apiValidation {
    ignoredProjects += setOf(
        "samples:backend-ktor",
        "samples:android-passkey",
        "samples:ios-passkey",
        "platform:bom",
        "platform:constraints"
    )
}
