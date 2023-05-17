package org.fiware.gaiax.common.repository;

import io.github.wistefan.mapping.EntityVOMapper;
import io.github.wistefan.mapping.JavaObjectMapper;
import org.fiware.gaiax.common.configuration.GeneralProperties;
import org.fiware.gaiax.common.mapping.NGSIMapper;
import org.fiware.ngsi.api.EntitiesApiClient;

import javax.inject.Singleton;

@Singleton
public class TrustedIssuersRepository extends NgsiLdBaseRepository {
    public TrustedIssuersRepository(GeneralProperties generalProperties, EntitiesApiClient entitiesApi, JavaObjectMapper javaObjectMapper, NGSIMapper ngsiMapper, EntityVOMapper entityVOMapper) {
        super(generalProperties, entitiesApi, javaObjectMapper, ngsiMapper, entityVOMapper);
    }
}
