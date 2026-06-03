plugins {
    id("webauthn.kotlin.multiplatform")
    id("webauthn.published-library")
}

kotlin {
    jvm()

    sourceSets {
        commonMain.dependencies {
            api(project(":core:webauthn-model"))
            api(project(":core:webauthn-core"))
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
