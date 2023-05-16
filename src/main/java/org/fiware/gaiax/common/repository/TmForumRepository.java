package org.fiware.gaiax.common.repository;

import io.github.wistefan.mapping.EntityVOMapper;
import io.github.wistefan.mapping.JavaObjectMapper;
import org.fiware.gaiax.common.exception.TmForumException;
import org.fiware.gaiax.common.mapping.NGSIMapper;
import org.fiware.gaiax.common.configuration.GeneralProperties;
import org.fiware.gaiax.common.exception.TmForumExceptionReason;
import org.fiware.ngsi.api.EntitiesApiClient;
import reactor.core.publisher.Mono;

import javax.inject.Singleton;
import java.net.URI;
import java.util.List;

@Singleton
public class TmForumRepository extends NgsiLdBaseRepository {

	public TmForumRepository(GeneralProperties generalProperties, EntitiesApiClient entitiesApi,
							 EntityVOMapper entityVOMapper, NGSIMapper ngsiMapper, JavaObjectMapper javaObjectMapper) {
		super(generalProperties, entitiesApi, javaObjectMapper, ngsiMapper, entityVOMapper);
	}

	public <T> Mono<T> get(URI id, Class<T> entityClass) {
		return retrieveEntityById(id)
				.flatMap(entityVO -> entityVOMapper.fromEntityVO(entityVO, entityClass));
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
					throw new TmForumException("Was not able to list entities.", t, TmForumExceptionReason.UNKNOWN);
				});
	}

}