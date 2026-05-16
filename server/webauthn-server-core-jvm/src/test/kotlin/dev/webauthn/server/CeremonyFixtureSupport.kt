package dev.webauthn.server

import dev.webauthn.core.CeremonyType
import dev.webauthn.core.ChallengeSession
import dev.webauthn.model.Challenge
import dev.webauthn.model.CollectedClientData
import dev.webauthn.model.Origin
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import java.io.InputStreamReader
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

private val ceremonyFixtureJson = Json.Default

internal fun loadRegistrationCeremonyFixture(
    path: String,
    classLoader: ClassLoader,
): RegistrationCeremonyFixture {
    val fixture: RegistrationCeremonyFixture = classLoader.getResourceAsStream(path).use { stream ->
        requireNotNull(stream) { "Missing fixture: $path" }
        ceremonyFixtureJson.decodeFromString<RegistrationCeremonyFixture>(
            InputStreamReader(stream, Charsets.UTF_8).readText(),
        )
    }
    require(fixture.kind == CEREMONY_KIND_REGISTRATION) {
        "Fixture $path must declare kind=$CEREMONY_KIND_REGISTRATION, was ${fixture.kind}"
    }
    return fixture
}

internal fun loadAuthenticationCeremonyFixture(
    path: String,
    classLoader: ClassLoader,
): AuthenticationCeremonyFixture {
    val fixture: AuthenticationCeremonyFixture = classLoader.getResourceAsStream(path).use { stream ->
        requireNotNull(stream) { "Missing fixture: $path" }
        ceremonyFixtureJson.decodeFromString<AuthenticationCeremonyFixture>(
            InputStreamReader(stream, Charsets.UTF_8).readText(),
        )
    }
    require(fixture.kind == CEREMONY_KIND_AUTHENTICATION) {
        "Fixture $path must declare kind=$CEREMONY_KIND_AUTHENTICATION, was ${fixture.kind}"
    }
    return fixture
}

internal fun RegistrationCeremonyFixture.userHandle(): UserHandle =
    UserHandle.parseOrThrow(relyingParty.userHandle)

internal fun RegistrationCeremonyFixture.registrationSession(): ChallengeSession {
    return ChallengeSession(
        challenge = Challenge.parseOrThrow(relyingParty.challenge),
        rpId = RpId.parseOrThrow(relyingParty.rpId),
        origin = Origin.parseOrThrow(relyingParty.origin),
        userName = relyingParty.userName,
        createdAtEpochMs = 0L,
        expiresAtEpochMs = Long.MAX_VALUE,
        type = CeremonyType.REGISTRATION,
    )
}

internal fun RegistrationCeremonyFixture.registrationClientData(): CollectedClientData {
    return CollectedClientData(
        type = "webauthn.create",
        challenge = Challenge.parseOrThrow(relyingParty.challenge),
        origin = Origin.parseOrThrow(relyingParty.origin),
    )
}

internal fun AuthenticationCeremonyFixture.userHandle(): UserHandle =
    UserHandle.parseOrThrow(relyingParty.userHandle)

internal fun AuthenticationCeremonyFixture.authenticationClientData(): CollectedClientData {
    return CollectedClientData(
        type = "webauthn.get",
        challenge = Challenge.parseOrThrow(relyingParty.challenge),
        origin = Origin.parseOrThrow(relyingParty.origin),
    )
}

internal fun RegistrationResponseFixture.toDto(): RegistrationResponseDto {
    return RegistrationResponseDto(
        id = id,
        rawId = rawId,
        response = RegistrationResponsePayloadDto(
            clientDataJson = clientDataJson,
            attestationObject = attestationObject,
        ),
    )
}

internal fun AuthenticationResponseFixture.toDto(): AuthenticationResponseDto {
    return AuthenticationResponseDto(
        id = id,
        rawId = rawId,
        response = AuthenticationResponsePayloadDto(
            clientDataJson = clientDataJson,
            authenticatorData = authenticatorData,
            signature = signature,
            userHandle = userHandle,
        ),
    )
}

internal fun RegistrationResponseFixture.toBrowserCredentialJson(): String {
    return """
        {
          "id": "$id",
          "rawId": "$rawId",
          "type": "public-key",
          "response": {
            "clientDataJSON": "$clientDataJson",
            "attestationObject": "$attestationObject"
          },
          "clientExtensionResults": {}
        }
    """.trimIndent()
}

internal fun AuthenticationResponseFixture.toBrowserCredentialJson(): String {
    val userHandleJson = userHandle?.let { """,
            "userHandle": "$it"""" } ?: ""
    return """
        {
          "id": "$id",
          "rawId": "$rawId",
          "type": "public-key",
          "response": {
            "clientDataJSON": "$clientDataJson",
            "authenticatorData": "$authenticatorData",
            "signature": "$signature"$userHandleJson
          },
          "clientExtensionResults": {}
        }
    """.trimIndent()
}

@Serializable
internal data class CeremonyRelyingPartyFixture(
    val rpId: String,
    val origin: String,
    val challenge: String,
    val userName: String,
    val userHandle: String,
)

@Serializable
internal data class RegistrationResponseFixture(
    val id: String,
    val rawId: String,
    val clientDataJson: String,
    val attestationObject: String,
)

@Serializable
internal data class AuthenticationResponseFixture(
    val id: String,
    val rawId: String,
    val clientDataJson: String,
    val authenticatorData: String,
    val signature: String,
    val userHandle: String? = null,
)

@Serializable
internal data class FixtureCredentialSeed(
    val credentialId: String,
    val publicKeyCose: String,
    val signCount: Long,
)

@Serializable
internal data class RegistrationExpectedFixture(
    val accept: Boolean,
    val flags: List<String>,
    val signCount: Long,
    val credentialIdPresent: Boolean,
    val credentialId: String,
    val aaguid: String,
    val publicKeyCose: String,
    val alg: Int,
    val extensionsPresent: Boolean,
)

@Serializable
internal data class AuthenticationExpectedFixture(
    val accept: Boolean,
    val flags: List<String>,
    val signCount: Long,
    val credentialIdPresent: Boolean,
    val credentialId: String,
    val alg: Int,
    val extensionsPresent: Boolean,
)

@Serializable
internal data class RegistrationCeremonyFixture(
    val name: String,
    val kind: String,
    val relyingParty: CeremonyRelyingPartyFixture,
    val response: RegistrationResponseFixture,
    val expected: RegistrationExpectedFixture,
)

@Serializable
internal data class AuthenticationCeremonyFixture(
    val name: String,
    val kind: String,
    val relyingParty: CeremonyRelyingPartyFixture,
    val credential: FixtureCredentialSeed,
    val response: AuthenticationResponseFixture,
    val expected: AuthenticationExpectedFixture,
)

private const val CEREMONY_KIND_REGISTRATION = "registration"
private const val CEREMONY_KIND_AUTHENTICATION = "authentication"
