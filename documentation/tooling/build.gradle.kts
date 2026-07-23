import org.gradle.api.tasks.JavaExec

plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

application {
    mainClass.set("dev.webauthn.documentation.DocumentationExamples")
}

dependencies {
    testImplementation(kotlin("test-junit5"))
    testImplementation(libs.junit.jupiter)
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.register<JavaExec>("checkDocumentation") {
    group = "verification"
    description = "Checks documentation directives, source synchronization, syntax, and inventory freshness."
    dependsOn(tasks.named("classes"))
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set(application.mainClass)
    args("check", rootProject.layout.projectDirectory.asFile.absolutePath)
}

tasks.register<JavaExec>("updateDocumentation") {
    group = "documentation"
    description = "Updates source-backed documentation blocks and the generated inventory."
    dependsOn(tasks.named("classes"))
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set(application.mainClass)
    args("update", rootProject.layout.projectDirectory.asFile.absolutePath)
}
