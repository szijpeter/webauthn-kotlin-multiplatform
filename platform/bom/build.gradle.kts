plugins {
    `java-platform`
}

javaPlatform {
    allowDependencies()
}

dependencies {
    constraints {
        api("${project.group}:webauthn-model:${project.version}")
        api("${project.group}:webauthn-serialization-kotlinx:${project.version}")
        api("${project.group}:webauthn-core:${project.version}")
        api("${project.group}:webauthn-crypto-api:${project.version}")
        api("${project.group}:webauthn-server-jvm-crypto:${project.version}")
        api("${project.group}:webauthn-server-core-jvm:${project.version}")
        api("${project.group}:webauthn-server-ktor:${project.version}")
        api("${project.group}:webauthn-client-core:${project.version}")
        api("${project.group}:webauthn-client-android:${project.version}")
        api("${project.group}:webauthn-client-ios:${project.version}")
        api("${project.group}:webauthn-network-ktor-client:${project.version}")
        api("${project.group}:webauthn-attestation-mds:${project.version}")
    }
}
