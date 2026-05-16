package dev.webauthn.network

import dev.webauthn.core.OriginMetadataProvider
import dev.webauthn.model.Origin
import dev.webauthn.model.getOrNull
import dev.webauthn.runtime.suspendCatchingNonCancellation
import dev.webauthn.serialization.RelatedOriginsDto
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode

/**
 * Implementation of [OriginMetadataProvider] using Ktor HttpClient.
 */
public class KtorOriginMetadataProvider(
    private val httpClient: HttpClient,
) : OriginMetadataProvider {

    override suspend fun getRelatedOrigins(primaryOrigin: Origin): Set<Origin> {
        val url = "${primaryOrigin.toString().removeSuffix("/")}/.well-known/webauthn"
        return suspendCatchingNonCancellation {
            val response = httpClient.get(url)
            if (response.status == HttpStatusCode.OK) {
                val dto = response.body<RelatedOriginsDto>()
                dto.origins
                    .mapNotNull(::parseOriginOrNull)
                    .toSet()
            } else {
                emptySet()
            }
        }.getOrElse {
            // Fail closed on fetch/parse errors by treating related origins as unavailable.
            emptySet()
        }
    }
}

private fun parseOriginOrNull(encodedOrigin: String): Origin? {
    return Origin.parse(encodedOrigin).getOrNull()
}
