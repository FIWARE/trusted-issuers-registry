package org.fiware.iam.tir.rest;

import changeMe.JwtProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.wistefan.mapping.JavaObjectMapper;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration;
import io.micronaut.test.annotation.MockBean;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import lombok.SneakyThrows;
import org.fiware.iam.common.configuration.GeneralProperties;
import org.fiware.iam.did.api.DidApiTestClient;
import org.fiware.iam.did.api.DidApiTestSpec;
import org.fiware.iam.did.model.DIDDocumentVO;
import org.fiware.iam.did.model.JWKVO;
import org.fiware.iam.did.model.JsonWebKey2020VerificationMethodVO;
import org.fiware.iam.tir.issuers.TrustedIssuer;
import org.fiware.iam.tir.repository.DidService;
import org.fiware.iam.tir.repository.InMemoryPartiesRepo;
import org.fiware.ngsi.api.EntitiesApiClient;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@MicronautTest(packages = {"org.fiware.iam.tir"})
public class DidRegistryIT extends NGSIBasedTest implements DidApiTestSpec {


    private final DidApiTestClient apiClient;

    private final InMemoryPartiesRepo partyRepo;

    public final DidService didService;

    private final SignatureGeneratorConfiguration signature;

    @MockBean(DidService.class)
    public DidService mockDidService() {
        return mock(DidService.class);
    }

    private static final DIDDocumentVO SOME_DID_DOCUMENT = new DIDDocumentVO()
            .id("did:web:someDid")
            .addVerificationMethodItem(new JsonWebKey2020VerificationMethodVO().id("did:web:someDid").publicKeyJwk(new JWKVO().x5u("example.com/cert")));

    public DidRegistryIT(EntitiesApiClient entitiesApiClient, JavaObjectMapper javaObjectMapper, ObjectMapper objectMapper, GeneralProperties generalProperties, DidApiTestClient apiClient, InMemoryPartiesRepo partyRepo, DidService didService, SignatureGeneratorConfiguration signature) {
        super(entitiesApiClient, javaObjectMapper, objectMapper, generalProperties);
        this.apiClient = apiClient;
        this.partyRepo = partyRepo;
        this.didService = didService;
        this.signature = signature;
    }

    @Test
    @Override
    public void getDIDDocument200() throws Exception {
        String bearerToken = new JwtProvider(signature).builder().toBearer();
        when(didService.retrieveDidDocument("did:web:someDid")).thenReturn(Optional.of(SOME_DID_DOCUMENT));
        when(didService.getCertificate(SOME_DID_DOCUMENT)).thenReturn(Optional.of("someCert"));

        createIssuer(new TrustedIssuer("did:web:someId").setIssuer("did:web:someDid"));
        partyRepo.updateParties();
        HttpResponse<DIDDocumentVO> answer = apiClient.getDIDDocument(bearerToken, "did:web:someDid", null);
        assertEquals(HttpStatus.OK, answer.getStatus());

        assertEquals(toJson(SOME_DID_DOCUMENT), toJson(answer.getBody().get()));
    }

    @SneakyThrows
    private String toJson(Object obj) {
        return getObjectMapper().writeValueAsString(obj);
    }

    @Disabled("Test client verifies the parameter already")
    @Override
    public void getDIDDocument400() throws Exception {
        HttpResponse<DIDDocumentVO> answer = apiClient.getDIDDocument(null, null);
        assertEquals(HttpStatus.BAD_REQUEST, answer.getStatus());
    }

    @Test
    @Override
    public void getDIDDocument401() throws Exception {
        assertThat(callAndCatch(() -> apiClient.getDIDDocument(null, "did:ebsi:unknown", null)))
                .extracting(HttpResponse::getStatus)
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @Override
    public void getDIDDocument404() throws Exception {
        HttpResponse<DIDDocumentVO> answer = apiClient.getDIDDocument("did:ebsi:unknown", null);
        assertEquals(HttpStatus.NOT_FOUND, answer.getStatus());
    }

    @Disabled("Can't provoke it")
    @Override
    public void getDIDDocument500() throws Exception {

    }
}
