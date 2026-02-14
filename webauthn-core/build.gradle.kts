plugins {
    id("webauthn.kotlin.multiplatform")
}

kotlin {
    jvm()

    sourceSets {
        commonMain.dependencies {
            api(project(":webauthn-model"))
            implementation(libs.kotlinx.datetime)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
