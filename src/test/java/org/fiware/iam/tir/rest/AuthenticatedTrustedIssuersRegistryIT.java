package org.fiware.iam.tir.rest;

import changeMe.JwtProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.wistefan.mapping.JavaObjectMapper;
import io.micronaut.context.annotation.Property;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.fiware.iam.common.configuration.GeneralProperties;
import org.fiware.iam.tir.api.TirApiTestClient;
import org.fiware.iam.tir.api.TirApiTestSpec;
import org.fiware.iam.tir.issuers.TrustedIssuer;
import org.fiware.iam.tir.model.IssuerVO;
import org.fiware.iam.tir.model.IssuersResponseVO;
import org.fiware.ngsi.api.EntitiesApiClient;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

@MicronautTest(packages = {"org.fiware.iam.tir"})
@Property(name = "general.trustedIssuersRegistry.authenticated", value = "true")
public class AuthenticatedTrustedIssuersRegistryIT extends NGSIBasedTest implements TirApiTestSpec {

    private final SignatureGeneratorConfiguration signature;
    final TirApiTestClient apiClient;

    public AuthenticatedTrustedIssuersRegistryIT(EntitiesApiClient entitiesApiClient, JavaObjectMapper javaObjectMapper, ObjectMapper objectMapper, GeneralProperties generalProperties, SignatureGeneratorConfiguration signature, TirApiTestClient apiClient1) {
        super(entitiesApiClient, javaObjectMapper, objectMapper, generalProperties);
        this.signature = signature;
        this.apiClient = apiClient1;
    }

    private String genToken(){
       return new JwtProvider(signature).builder().subject("test").issuer("issuer").toBearer();
    }

    @Test
    @Override
    public void getIssuer200() throws Exception {
        createIssuer(new TrustedIssuer("someId").setIssuer("someDid"));
        assertEquals(HttpStatus.OK, apiClient.getIssuer(genToken(), "someDid").getStatus());
    }

    @Override
    public void getIssuer400() throws Exception {
    }

    @Test
    @Override
    public void getIssuer401() throws Exception {
        createIssuer(new TrustedIssuer("someId").setIssuer("someDid"));
        HttpResponse<IssuerVO> response = callAndCatch(() -> apiClient.getIssuer("someDid"));
        assertEquals(HttpStatus.UNAUTHORIZED,response.getStatus());
    }

    @Override
    public void getIssuer404() throws Exception {
    }

    @Override
    public void getIssuer500() throws Exception {
    }

    @Test
    @Override
    public void getIssuers200() throws Exception {
        createIssuer(new TrustedIssuer("someId").setIssuer("someDid"));
        createIssuer(new TrustedIssuer("someId2").setIssuer("someDid2"));

        HttpResponse<IssuersResponseVO> issuersResponse = apiClient.getIssuers(genToken(), 100, null);
        assertThat(issuersResponse).extracting(HttpResponse::getStatus).isEqualTo(HttpStatus.OK);

        IssuersResponseVO responseBody = issuersResponse.body();
        assertThat(responseBody).extracting(IssuersResponseVO::getItems).asList().hasSize(2);
    }

    @Override
    public void getIssuers400() throws Exception {
    }

    @Test
    @Override
    public void getIssuers401() throws Exception {
        createIssuer(new TrustedIssuer("someId").setIssuer("someDid"));
        HttpResponse<IssuersResponseVO> response = callAndCatch(() -> apiClient.getIssuers(100, null));
        assertEquals(HttpStatus.UNAUTHORIZED,response.getStatus());
    }

    @Override
    public void getIssuers500() throws Exception {
    }
}
