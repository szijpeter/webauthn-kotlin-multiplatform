plugins {
    kotlin("jvm")
}

kotlin {
    explicitApi()
    jvmToolchain(21)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
