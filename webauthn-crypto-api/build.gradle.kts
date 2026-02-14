plugins {
    id("webauthn.kotlin.multiplatform")
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
