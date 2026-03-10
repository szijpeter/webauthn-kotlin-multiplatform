package dev.webauthn.network

import dev.webauthn.core.OriginMetadataProvider
import dev.webauthn.model.Origin
import dev.webauthn.model.getOrNull
import dev.webauthn.serialization.RelatedOriginsDto
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.CancellationException

/**
 * Implementation of [OriginMetadataProvider] using Ktor HttpClient.
 */
public class KtorOriginMetadataProvider(
    private val httpClient: HttpClient
) : OriginMetadataProvider {

    override suspend fun getRelatedOrigins(primaryOrigin: Origin): Set<Origin> {
        val url = "${primaryOrigin.toString().removeSuffix("/")}/.well-known/webauthn"
        return try {
            val response = httpClient.get(url)
            if (response.status == HttpStatusCode.OK) {
                val dto = response.body<RelatedOriginsDto>()
                dto.origins.mapNotNull { origin -> Origin.parse(origin).getOrNull() }.toSet()
            } else {
                emptySet()
            }
        } catch (exception: CancellationException) {
            throw exception
        } catch (_: Exception) {
            // Fail closed on fetch/parse errors by treating related origins as unavailable.
            emptySet()
        }
    }
}
