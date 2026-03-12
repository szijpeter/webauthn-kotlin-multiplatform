import dev.detekt.gradle.Detekt
import dev.detekt.gradle.extensions.DetektExtension

plugins {
    `kotlin-dsl`
    alias(libs.plugins.detekt)
}

repositories {
    google()
    mavenCentral()
    gradlePluginPortal()
}

dependencies {
    implementation(libs.kotlin.gradle.plugin)
    implementation(libs.agp)
    implementation(libs.dokka.gradlePlugin)
    implementation(libs.bcv.gradlePlugin)
    implementation(libs.vanniktech.mavenPublish.gradlePlugin)
}

extensions.configure<DetektExtension> {
    config.setFrom(file("../config/detekt/detekt.yml"))
    buildUponDefaultConfig = true
    ignoreFailures = false
    parallel = true
}

tasks.withType<Detekt>().configureEach {
    exclude("**/build/**")
    reports {
        checkstyle.required.set(true)
        html.required.set(true)
    }
}
