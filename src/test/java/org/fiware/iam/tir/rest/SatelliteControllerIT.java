package org.fiware.iam.tir.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.wistefan.mapping.JavaObjectMapper;
import io.micronaut.http.HttpMessage;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import lombok.Data;
import lombok.SneakyThrows;
import org.fiware.iam.common.configuration.GeneralProperties;
import org.fiware.iam.satellite.api.SatelliteApiTestSpec;
import org.fiware.iam.satellite.model.*;
import org.fiware.ngsi.api.EntitiesApiClient;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.fiware.iam.tir.rest.TestUtils.readConfig;
import static org.fiware.iam.tir.rest.TestUtils.strip;
import static org.junit.jupiter.api.Assertions.assertEquals;

@MicronautTest(packages = {"org.fiware.iam.tir"})
public class SatelliteControllerIT extends NGSIBasedTest implements SatelliteApiTestSpec {

    private final SatelliteApiTestClientFixed testClient;

    public SatelliteControllerIT(EntitiesApiClient entitiesApiClient, JavaObjectMapper javaObjectMapper, ObjectMapper objectMapper, GeneralProperties generalProperties, SatelliteApiTestClientFixed testClient) {
        super(entitiesApiClient, javaObjectMapper, objectMapper, generalProperties);
        this.testClient = testClient;
    }


    @Test
    @Override
    public void getParties200() throws Exception {
        ApplicationConfig applicationConfig = readConfigOfApplication();

        HttpResponse<PartiesResponseVO> partiesResponse = testClient.getParties("Bearer " + createSignedJWTClientToken(), null, null);

        assertThat(partiesResponse).extracting(HttpResponse::getStatus).isEqualTo(HttpStatus.OK);
        PartiesResponseVO parties = partiesResponse.getBody(PartiesResponseVO.class).get();
        DecodedJWT decodedJWT = JWT.decode(parties.getPartiesToken());
        assertThat(decodedJWT).isNotNull();
        // Verify correct signature and content
        JWTVerifier jwtVerifier = JWT
                .require(Algorithm.RSA256(applicationConfig.iShareConfig.getPublicKey()))
                .withAudience("EU.EORI.FIWARECLIENT")
                .withSubject("EU.EORI.FIWARESATELLITE")
                .withIssuer("EU.EORI.FIWARESATELLITE")
                .withArrayClaim("scope", "iSHARE")
                .build();
        jwtVerifier.verify(decodedJWT);
        List<String> serverCertificateChain = decodedJWT.getHeaderClaim("x5c").asList(String.class);
        assertThat(serverCertificateChain).isEqualTo(applicationConfig.iShareConfig.getEncodedCertificateChain());
        PartiesInfoVO partiesInfo = decodedJWT.getClaim("parties_info").as(PartiesInfoVO.class);
        assertThat(partiesInfo).extracting(PartiesInfoVO::getCount).isEqualTo(1);
        PartyVO party = partiesInfo.getData().get(0);
        assertThat(party.getCertificates()).hasSize(1);
        CertificateVO certificate = party.getCertificates().get(0);
        assertThat(certificate.getX5c()).isEqualTo(strip(applicationConfig.iShareConfig.getParties().get(0).crt()));
    }

    @Test
    @Override
    public void getParties401() throws Exception {
        assertThat(callAndCatch(() ->
                testClient.getParties("Bearer invalidToken", null, null)))
                .extracting(HttpResponse::getStatus)
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @Override
    public void getPartyById200() throws Exception {
        ApplicationConfig applicationConfig = readConfigOfApplication();
        HttpResponse<PartyResponseVO> response = testClient.getPartyById("Bearer " + createSignedJWTClientToken(), "EU.EORI.FIWARECLIENT");
        assertThat(response).extracting(HttpResponse::getStatus).isEqualTo(HttpStatus.OK);
        PartyResponseVO body = response.getBody(PartyResponseVO.class).get();
        DecodedJWT decodedJWT = JWT.decode(body.getPartyToken());
        assertThat(decodedJWT).isNotNull();
        // Verify correct signature and content
        JWTVerifier jwtVerifier = JWT
                .require(Algorithm.RSA256(applicationConfig.iShareConfig.getPublicKey()))
                .withAudience("EU.EORI.FIWARECLIENT")
                .withSubject("EU.EORI.FIWARESATELLITE")
                .withIssuer("EU.EORI.FIWARESATELLITE")
                .withArrayClaim("scope", "iSHARE")
                .build();
        jwtVerifier.verify(decodedJWT);
        PartyVO partyInfo = decodedJWT.getClaim("party_info").as(PartyVO.class);

        assertThat(partyInfo.getCertificates().get(0).getX5c()).isEqualTo(strip(applicationConfig.iShareConfig.getParties().get(0).crt()));
    }

    @Test
    @Override
    public void getPartyById404() throws Exception {
        HttpResponse<PartyResponseVO> response = testClient.getPartyById("Bearer " + createSignedJWTClientToken(), "some.unknown.party");
        assertThat(response).extracting(HttpResponse::getStatus).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    @Override
    public void getPartyById401() throws Exception {
        assertThat(callAndCatch(() ->
                testClient.getPartyById("Bearer invalidToken", "EU.EORI.FIWARECLIENT")))
                .extracting(HttpResponse::getStatus)
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private String createSignedJWTClientToken() {
        IShareConfig clientConfig = readConfig("client_fiware.yaml");
        Instant now = Instant.now();
        return JWT.create()
                .withAudience("someAudience")
                .withIssuer(clientConfig.getId())
                .withSubject(clientConfig.getId())
                .withIssuedAt(now)
                .withNotBefore(now)
                .withClaim("client_id", "EU.EORI.FIWARECLIENT")
                .withExpiresAt(now.plusSeconds(30))
                .withHeader(Map.of("x5c", clientConfig.getEncodedCertificateChain()))
                .sign(Algorithm.RSA256(clientConfig.getPublicKey(), clientConfig.getPrivateKey()));
    }

    @Test
    @Override
    public void getToken200() throws Exception {
        String signedToken = createSignedJWTClientToken();

        HttpResponse<TokenResponseVO> token = testClient.getToken("Bearer " + signedToken, "client_credentials", "EU.EORI.FIWARECLIENT", "iSHARE", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", signedToken);
        assertThat(token).isNotNull();
        assertThat(token).extracting(HttpResponse::getStatus).isEqualTo(HttpStatus.OK);
        assertThat(token).extracting(HttpMessage::getBody).isNotNull();
        TokenResponseVO body = token.body();
        assertThat(body).extracting(TokenResponseVO::getExpiresIn, TokenResponseVO::getScope, TokenResponseVO::getTokenType).containsExactly(3600, "iSHARE", "Bearer");
        DecodedJWT receivedToken = JWT.decode(body.getAccessToken());
        Claim x5c = receivedToken.getHeaderClaim("x5c");
        List<String> serverCertificateChain = x5c.asList(String.class);

        ApplicationConfig applicationConfig = readConfigOfApplication();

        // Response has the satellite's cert chain included
        assertThat(serverCertificateChain).isEqualTo(applicationConfig.iShareConfig.getEncodedCertificateChain());
        // Verify correct signature and content
        JWTVerifier jwtVerifier = JWT
                .require(Algorithm.RSA256(applicationConfig.iShareConfig.getPublicKey()))
                .withAudience("EU.EORI.FIWARESATELLITE")
                .withSubject("EU.EORI.FIWARESATELLITE")
                .withIssuer("EU.EORI.FIWARESATELLITE")
                .withClaim("client_id", "EU.EORI.FIWARECLIENT")
                .build();
        jwtVerifier.verify(receivedToken);
    }

    @Test
    @Override
    public void getToken400() throws Exception {
        assertThat(callAndCatch(() ->
                testClient.getToken("Bearer irrelevant", "client_credentials", "EU.EORI.FIWARECLIENT", "iSHARE", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "invalid")))
                .extracting(HttpResponse::getStatus)
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Disabled("Since the endpoint is set to anonymous, even an invalid token will be passed since it is not required.")
    @Test
    @Override
    public void getToken401() throws Exception {
        assertThat(callAndCatch(() ->
                testClient.getToken("Bearer invalidToken", "client_credentials", "EU.EORI.FIWARECLIENT", "iSHARE", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", createSignedJWTClientToken())))
                .extracting(HttpResponse::getStatus)
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @Override
    public void getTrustedList200() throws Exception {
        String signedToken = createSignedJWTClientToken();

        HttpResponse<TrustedListResponseVO> trustedList = testClient.getTrustedList("Bearer " + signedToken);
        assertEquals(HttpStatus.OK, trustedList.getStatus());
        DecodedJWT decodedJWT = JWT.decode(trustedList.body().getTrustedListToken());

        ApplicationConfig applicationConfig = readConfigOfApplication();
        // Verify correct signature and content
        JWTVerifier jwtVerifier = JWT
                .require(Algorithm.RSA256(applicationConfig.iShareConfig.getPublicKey()))
                .withAudience("EU.EORI.FIWARECLIENT")
                .withSubject("EU.EORI.FIWARESATELLITE")
                .withIssuer("EU.EORI.FIWARESATELLITE")
                .withArrayClaim("scope", "iSHARE")
                .build();
        jwtVerifier.verify(decodedJWT);

        Map<String, Claim> claims = decodedJWT.getClaims();
        List<TrustedCAVO> listOfTrustedCAs = claims.get("trusted_list").asList(TrustedCAVO.class);

        assertThat(listOfTrustedCAs).hasSize(1);
        assertThat(listOfTrustedCAs).contains(new TrustedCAVO()
                .subject("EMAILADDRESS=test@fiware.org, CN=FIWARE-CA, O=FIWARE, L=Berlin, ST=Berlin, C=DE")
                .certificateFingerprint("8ECB9BD8E0FE12D7368ACDE12905E823812C34A71F97439D9E42383477C94E2B")
                .status("granted")
                .validity("valid"));
    }

    @Test
    @Override
    public void getTrustedList401() throws Exception {
        assertThat(callAndCatch(() ->
                testClient.getTrustedList("Bearer invalidToken")))
                .extracting(HttpResponse::getStatus)
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }



    @SneakyThrows
    private ApplicationConfig readConfigOfApplication() {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        return mapper.readValue(new File("src/test/resources/application.yaml"), ApplicationConfig.class);
    }

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    static class ApplicationConfig {
        @JsonProperty("satellite")
        IShareConfig iShareConfig;
    }
}