package org.fiware.iam.tir.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.wistefan.mapping.AdditionalPropertyMixin;
import io.github.wistefan.mapping.JavaObjectMapper;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.fiware.iam.common.configuration.GeneralProperties;
import org.fiware.iam.tir.issuers.TrustedIssuer;
import org.fiware.ngsi.api.EntitiesApiClient;
import org.fiware.ngsi.model.AdditionalPropertyVO;
import org.fiware.ngsi.model.EntityListVO;
import org.fiware.ngsi.model.EntityVO;
import org.junit.jupiter.api.BeforeEach;

import java.net.URL;
import java.util.Objects;
import java.util.concurrent.Callable;

@RequiredArgsConstructor
public abstract class NGSIBasedTest {
    private final EntitiesApiClient entitiesApiClient;
    private final JavaObjectMapper javaObjectMapper;
    @Getter
    private final ObjectMapper objectMapper;
    private final GeneralProperties generalProperties;

    public void createIssuer(TrustedIssuer someIssuer) {
        EntityVO entityVO = javaObjectMapper.toEntityVO(someIssuer);
        entitiesApiClient.createEntity(entityVO, null).block();
    }
    @BeforeEach
    public void cleanUp() {
        this.objectMapper
                .addMixIn(AdditionalPropertyVO.class, AdditionalPropertyMixin.class);
        this.objectMapper.findAndRegisterModules();
        EntityListVO entityVOS = entitiesApiClient.queryEntities(null,
                null,
                null,
                TrustedIssuer.TYPE_TRUSTED_ISSUER,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                1000,
                0,
                null,
                getLinkHeader(generalProperties.getContextUrl())).block();
        entityVOS.stream()
                .filter(Objects::nonNull)
                .map(EntityVO::getId)
                .filter(Objects::nonNull)
                .forEach(eId -> entitiesApiClient.removeEntityById(eId, null, null).block());
    }

    protected String getLinkHeader(URL contextUrl) {
        return String.format("<%s>; rel=\"http://www.w3.org/ns/json-ld#context\"; type=\"application/ld+json",
                contextUrl);
    }

    // Helper method to catch potential http exceptions and return the status code.
    public <T> HttpResponse<T> callAndCatch(Callable<HttpResponse<T>> request) throws Exception {
        try {
            return request.call();
        } catch (HttpClientResponseException e) {
            return (HttpResponse<T>) e.getResponse();
        }
    }
}
