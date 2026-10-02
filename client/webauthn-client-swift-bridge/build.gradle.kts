import co.touchlab.skie.configuration.EnumInterop
import co.touchlab.skie.configuration.FlowInterop
import co.touchlab.skie.configuration.SealedInterop
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

plugins {
    id("webauthn.kotlin.multiplatform")
    alias(libs.plugins.skie)
}

skie {
    analytics {
        enabled.set(false)
    }
    build {
        produceDistributableFramework()
    }
    features {
        group {
            FlowInterop.Enabled(false)
            EnumInterop.Enabled(false)
            SealedInterop.Enabled(false)
        }
    }
}

kotlin {
    val appleFrameworkVersion = project.version
        .toString()
        .substringBefore('-')
        .takeIf { it.matches(Regex("""\d+\.\d+\.\d+""")) }
        ?: "0.0.0"
    val webAuthnBridge = XCFramework("WebAuthnBridge")
    listOf(
        iosArm64(),
        iosSimulatorArm64(),
    ).forEach { target ->
        target.binaries.framework {
            baseName = "WebAuthnBridge"
            isStatic = true
            binaryOption("bundleId", "dev.webauthn.swift.bridge")
            binaryOption("bundleShortVersionString", appleFrameworkVersion)
            webAuthnBridge.add(this)
        }
    }

    sourceSets {
        iosMain.dependencies {
            implementation(project(":client:webauthn-client-platform"))
            implementation(project(":client:webauthn-client-json-core"))
            implementation(project(":core:webauthn-json-kotlinx"))
            implementation(project(":core:webauthn-runtime-core"))
            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.kotlinx.serialization.json)
        }
        iosTest.dependencies {
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

val privacyManifest = rootProject.layout.projectDirectory.file("swift/Resources/PrivacyInfo.xcprivacy")
val projectLicense = rootProject.layout.projectDirectory.file("LICENSE")
val thirdPartyNotices = rootProject.layout.projectDirectory.file("swift/THIRD_PARTY_NOTICES.txt")
val releaseXCFramework = layout.buildDirectory.dir("XCFrameworks/release/WebAuthnBridge.xcframework")
val assembleReleaseXCFramework = tasks.named("assembleWebAuthnBridgeReleaseXCFramework")
val postprocessReleaseXCFramework = tasks.register<Exec>("postprocessWebAuthnBridgeReleaseXCFramework") {
    dependsOn(assembleReleaseXCFramework)
    inputs.file(privacyManifest)
    inputs.file(projectLicense)
    inputs.file(thirdPartyNotices)
    commandLine(
        rootProject.layout.projectDirectory.file("tools/swift/postprocess-xcframework.sh").asFile.absolutePath,
        releaseXCFramework.get().asFile.absolutePath,
        privacyManifest.asFile.absolutePath,
        projectLicense.asFile.absolutePath,
        thirdPartyNotices.asFile.absolutePath,
    )
}
assembleReleaseXCFramework.configure {
    finalizedBy(postprocessReleaseXCFramework)
}
