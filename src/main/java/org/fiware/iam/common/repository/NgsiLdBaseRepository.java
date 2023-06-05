package org.fiware.iam.common.repository;

import io.github.wistefan.mapping.EntityVOMapper;
import io.github.wistefan.mapping.JavaObjectMapper;
import io.micronaut.cache.annotation.Cacheable;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import lombok.RequiredArgsConstructor;
import org.fiware.iam.common.configuration.GeneralProperties;
import org.fiware.iam.common.exception.NgsiLdRepositoryException;
import org.fiware.iam.common.mapping.NGSIMapper;
import org.fiware.ngsi.api.EntitiesApiClient;
import org.fiware.ngsi.model.EntityVO;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Base-Repository implementation for using the NGSI-LD API as a storage backend. Supports caching and asynchronous retrieval of entities.
 */
@RequiredArgsConstructor
public abstract class NgsiLdBaseRepository{

    /**
     * Name for the entities cache
     */
    private static final String ENTITIES_CACHE_NAME = "entities";

    protected final GeneralProperties generalProperties;
    protected final EntitiesApiClient entitiesApi;
    protected final JavaObjectMapper javaObjectMapper;
    protected final NGSIMapper ngsiMapper;
    protected final EntityVOMapper entityVOMapper;


    protected String getLinkHeader() {
        return String.format("<%s>; rel=\"http://www.w3.org/ns/json-ld#context\"; type=\"application/ld+json", generalProperties.getContextUrl());
    }

    /**
     * Retrieve entity from the broker or from the cache if they are available there.
     *
     * @param entityId id of the entity
     * @return the entity
     */
    @Cacheable(ENTITIES_CACHE_NAME)
    public Mono<EntityVO> retrieveEntityById(URI entityId) {
        return asyncRetrieveEntityById(entityId, generalProperties.getTenant(), null, null, null, getLinkHeader());
    }

    public <T> Mono<T> get(URI id, Class<T> entityClass) {
        return retrieveEntityById(id)
                .flatMap(entityVO -> entityVOMapper.fromEntityVO(entityVO, entityClass));
    }

    /**
     * Helper method for combining a stream of entites to a single mono.
     *
     * @param entityVOStream stream of entites
     * @param targetClass    target class to map them
     * @param <T>            type of the target
     * @return a mono, emitting a list of mapped entities
     */
    protected <T> Mono<List<T>> zipToList(Stream<EntityVO> entityVOStream, Class<T> targetClass) {
        return Mono.zip(
                entityVOStream.map(entityVO -> entityVOMapper.fromEntityVO(entityVO, targetClass)).toList(),
                oList -> Arrays.stream(oList).map(targetClass::cast).toList()
        );
    }

    /**
     * Uncached call to the broker
     */
    private Mono<EntityVO> asyncRetrieveEntityById(URI entityId, String ngSILDTenant, String attrs, String type, String options, String link) {
        return entitiesApi
                .retrieveEntityById(entityId, ngSILDTenant, attrs, type, options, link)
                .onErrorResume(this::handleClientException);
    }

    public <T> Mono<List<T>> findEntities(Integer offset, Integer limit, String entityType, Class<T> entityClass) {
        return entitiesApi.queryEntities(generalProperties.getTenant(),
                        null,
                        null,
                        entityType,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        limit,
                        offset,
                        null,
                        getLinkHeader())
                .map(List::stream)
                .flatMap(entityVOStream -> zipToList(entityVOStream, entityClass))
                .onErrorResume(t -> {
                    throw new NgsiLdRepositoryException("Was not able to list entities.", Optional.of(t));
                });
    }

    private Mono<EntityVO> handleClientException(Throwable e) {
        if (e instanceof HttpClientResponseException httpException && httpException.getStatus().equals(HttpStatus.NOT_FOUND)) {
            return Mono.empty();
        }
        throw new NgsiLdRepositoryException("Was not able to successfully call the broker.", Optional.of(e));
    }

}

