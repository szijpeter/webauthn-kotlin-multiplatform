plugins {
    id("webauthn.kotlin.multiplatform")
    id("webauthn.published-library")
}

kotlin {
    jvm()

    sourceSets {
        commonMain.dependencies {
            api(project(":webauthn-model"))
            api(project(":webauthn-core"))
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
