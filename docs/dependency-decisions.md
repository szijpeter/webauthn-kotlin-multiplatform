# Dependency Decisions

## Policy

1. Prefer Kotlin and Kotlinx libraries first.
2. Add third-party dependencies only when Kotlin/Kotlinx cannot satisfy a requirement.
3. Keep `webauthn-model` and `webauthn-core` free of platform/network dependencies.

## Current baseline

- Kotlin `2.2.20`
- AGP `9.0.0`
- Ktor `3.3.0`
- kotlinx.serialization `1.9.0`
- kotlinx.coroutines `1.10.2`
- kotlinx.datetime `0.7.1`

## Notes

- JVM crypto currently uses JCA/JCE from the JDK.
- No external crypto provider is used in V1 scaffold.
- Optional MDS support uses Ktor client + Kotlinx serialization only.
