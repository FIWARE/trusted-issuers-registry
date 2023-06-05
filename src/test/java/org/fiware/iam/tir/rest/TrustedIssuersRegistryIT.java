package org.fiware.iam.tir.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.wistefan.mapping.JavaObjectMapper;
import io.micronaut.http.HttpMessage;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.fiware.iam.common.configuration.GeneralProperties;
import org.fiware.iam.tir.api.TirApiTestClient;
import org.fiware.iam.tir.api.TirApiTestSpec;
import org.fiware.iam.tir.issuers.TrustedIssuer;
import org.fiware.iam.tir.model.IssuersResponseVO;
import org.fiware.ngsi.api.EntitiesApiClient;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

@MicronautTest(packages = {"org.fiware.iam.tir"})
public class TrustedIssuersRegistryIT extends NGSIBasedTest implements TirApiTestSpec {


    private final TirApiTestClient apiClient;

    public TrustedIssuersRegistryIT(EntitiesApiClient entitiesApiClient, JavaObjectMapper javaObjectMapper, ObjectMapper objectMapper, GeneralProperties generalProperties, TirApiTestClient apiClient) {
        super(entitiesApiClient, javaObjectMapper, objectMapper, generalProperties);
        this.apiClient = apiClient;
    }

    @Test
    @Override
    public void getIssuer200() throws Exception {
        createIssuer(new TrustedIssuer("someId").setIssuer("someDid"));
        assertEquals(HttpStatus.OK, apiClient.getIssuer("someDid").getStatus());
    }


    @Disabled("Test client verifies the parameter already")
    @Override
    public void getIssuer400() throws Exception {
        assertEquals(HttpStatus.BAD_REQUEST, apiClient.getIssuer(null).getStatus());
    }

    @Test
    @Override
    public void getIssuer404() throws Exception {
        assertEquals(HttpStatus.NOT_FOUND, apiClient.getIssuer("notExistingDid").getStatus());
    }

    @Disabled("Can't provoke it")
    @Override
    public void getIssuer500() throws Exception {

    }

    @Test
    @Override
    public void getIssuers200() throws Exception {
        createIssuer(new TrustedIssuer("someId").setIssuer("someDid"));
        createIssuer(new TrustedIssuer("someId2").setIssuer("someDid2"));

        HttpResponse<IssuersResponseVO> issuersResponse = apiClient.getIssuers(100, null);
        assertThat(issuersResponse).extracting(HttpResponse::getStatus).isEqualTo(HttpStatus.OK);

        IssuersResponseVO responseBody = issuersResponse.body();
        assertThat(responseBody).extracting(IssuersResponseVO::getItems).asList().hasSize(2);
    }

    @Test
    @Override
    public void getIssuers400() throws Exception {
        assertEquals(HttpStatus.BAD_REQUEST, callAndCatch(() -> apiClient.getIssuers(-1, null)).getStatus());
    }

    @Disabled("Can't provoke it")
    @Override
    public void getIssuers500() throws Exception {

    }


}