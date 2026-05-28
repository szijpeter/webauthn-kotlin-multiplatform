package dev.webauthn.core

import dev.webauthn.model.Origin

/**
 * Provides metadata for an origin, such as related origins.
 */
public interface OriginMetadataProvider {
    /**
     * Fetches and returns the set of allowed origins for the given primary origin.
     * This corresponds to fetching /.well-known/webauthn from the primary origin.
     */
    public suspend fun getRelatedOrigins(primaryOrigin: Origin): Set<Origin>
}

/**
 * Default implementation that returns no additional origins.
 */
public object NoOpOriginMetadataProvider : OriginMetadataProvider {
    /** Returns no related origins, limiting acceptance to the explicitly configured origin set. */
    override suspend fun getRelatedOrigins(primaryOrigin: Origin): Set<Origin> = emptySet()
}
