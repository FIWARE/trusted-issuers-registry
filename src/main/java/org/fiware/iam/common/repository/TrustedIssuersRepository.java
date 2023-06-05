package org.fiware.iam.common.repository;

import io.github.wistefan.mapping.EntityVOMapper;
import io.github.wistefan.mapping.JavaObjectMapper;
import org.fiware.iam.common.configuration.GeneralProperties;
import org.fiware.iam.common.mapping.NGSIMapper;
import org.fiware.ngsi.api.EntitiesApiClient;

import javax.inject.Singleton;

@Singleton
public class TrustedIssuersRepository extends NgsiLdBaseRepository {
    public TrustedIssuersRepository(GeneralProperties generalProperties, EntitiesApiClient entitiesApi, JavaObjectMapper javaObjectMapper, NGSIMapper ngsiMapper, EntityVOMapper entityVOMapper) {
        super(generalProperties, entitiesApi, javaObjectMapper, ngsiMapper, entityVOMapper);
    }
}
