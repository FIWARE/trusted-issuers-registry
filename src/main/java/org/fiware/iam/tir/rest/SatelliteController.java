package org.fiware.iam.tir.rest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.utils.SecurityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.satellite.api.SatelliteApi;
import org.fiware.iam.satellite.model.*;
import org.fiware.iam.tir.auth.CertificateMapper;
import org.fiware.iam.tir.auth.IShareJWT;
import org.fiware.iam.tir.auth.JWTService;
import org.fiware.iam.tir.configuration.Party;
import org.fiware.iam.tir.configuration.SatelliteProperties;
import org.fiware.iam.tir.repository.PartiesRepo;

import java.security.Principal;
import java.security.interfaces.RSAPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Controller("${general.basepath:/}")
@RequiredArgsConstructor
public class SatelliteController implements SatelliteApi {

    private static final String ALLOWED_GRANT_TYPE = "client_credentials";
    private static final String SCOPE_DELIMITER = " ";
    private static final String I_SHARE_SCOPE = "iSHARE";
    private static final String ALLOWED_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final PartiesRepo partiesRepo;
    private final JWTService jwtService;
    private final SatelliteProperties satelliteProperties;
    private final SecurityService securityService;
    private final IShareMapper mapper;
    private final CertificateMapper certificateMapper;

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @IShareJWT
    @Override
    public HttpResponse<PartiesResponseVO> getParties(@Nullable String eori, @Nullable String certificateSubjectName) {
        log.debug("Attempting to retrieve parties with eori {} and certificate subject name", eori, certificateSubjectName);
        Optional<String> optionalEori = Optional.ofNullable(eori);
        Optional<String> optionalCSN = Optional.ofNullable(certificateSubjectName);
        List<Party> partys = new ArrayList<>();
        if (optionalEori.isPresent()) {
            partiesRepo.getPartyById(optionalEori.get()).ifPresent(party -> partys.add(party));
        } else {
            partys.addAll(partiesRepo.getParties());
        }
        if (optionalCSN.isPresent()) {
            List<Party> updatedParties = new ArrayList<>();
            partys.stream().forEach(party -> {
                var clientCert = certificateMapper.getCertificates(party.crt()).get(0);
                if (clientCert.getSubjectX500Principal().getName().equals(optionalCSN.get())) {
                    updatedParties.add(party);
                }
            });
            partys.clear();
            partys.addAll(updatedParties);
        }

        List<PartyVO> partyVOS = partys.stream()
                .map(mapper::partyToPartyVO)
                .collect(Collectors.toList());

        PartiesInfoVO partiesInfoVO = new PartiesInfoVO().data(partyVOS).count(partyVOS.size());
        log.debug("Returning {} parties: {}", partiesInfoVO.getCount(), partiesInfoVO.getData());

        return HttpResponse.ok(new PartiesResponseVO().partiesToken(
                createToken(securityService.getAuthentication().map(Principal::getName),
                        Optional.empty(),
                        Map.of(),
                        Map.of("parties_info", OBJECT_MAPPER.convertValue(partiesInfoVO, Map.class)))));
    }

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @IShareJWT
    @Override
    public HttpResponse<PartyResponseVO> getPartyById(String partyId) {
        log.debug("Attempting to retrieve party {}", partyId);
        Optional<PartyVO> optionalParty = partiesRepo.getPartyById(partyId).map(mapper::partyToPartyVO);
        if (optionalParty.isEmpty()) {
            log.warn("Could not find party {}", partyId);
            return HttpResponse.notFound();
        }
        PartyInfoVO partyInfoVO = new PartyInfoVO().partyInfo(optionalParty.get());
        PartyResponseVO prv = new PartyResponseVO().partyToken(
                createToken(securityService.getAuthentication().map(Principal::getName),
                        Optional.empty(),
                        Map.of(),
                        OBJECT_MAPPER.convertValue(partyInfoVO, Map.class)));
        log.debug("Returning party {}", partyInfoVO);
        return HttpResponse.ok(prv);
    }

    @Secured({SecurityRule.IS_ANONYMOUS})
    @IShareJWT
    @Override
    public HttpResponse<TokenResponseVO> getToken(@Nullable String grantType, @Nullable String clientId, @Nullable String scope,
                                                  @Nullable String clientAssertionType, @Nullable String clientAssertion) {
        log.debug("Attempting to get Token for {},{},{},{},{}", grantType, clientId, scope, clientAssertionType, clientAssertion);
        if (!ALLOWED_GRANT_TYPE.equals(grantType)) {
            log.warn("Grant Type {} is not the expected '{}'", grantType, ALLOWED_GRANT_TYPE);
            throw new IllegalArgumentException(String.format("Grant_type needs to be %s.", ALLOWED_GRANT_TYPE));
        }
        if (scope == null || !Arrays.asList(scope.split(SCOPE_DELIMITER)).contains(I_SHARE_SCOPE)) {
            log.warn("Scope {} does not contain the expected '{}'", scope, I_SHARE_SCOPE);
            throw new IllegalArgumentException(String.format("Scope needs to contain %s.", I_SHARE_SCOPE));
        }
        if (!ALLOWED_ASSERTION_TYPE.equals(clientAssertionType)) {
            log.warn("Client Assertion Type {} is the expected {}", clientAssertionType, ALLOWED_ASSERTION_TYPE);
            throw new IllegalArgumentException(
                    String.format("Assertion type needs to be %s.", ALLOWED_ASSERTION_TYPE));
        }
        if (partiesRepo.getPartyById(clientId).isEmpty()) {
            log.warn("Could not find client {} in known parties: {}.", clientId, partiesRepo.getParties().stream().map(Party::id).collect(Collectors.toSet()));
            throw new IllegalArgumentException(String.format("Unknown client %s", clientId));
        }
        jwtService.validateJWT(clientAssertion);
        TokenResponseVO tokenResponseVO = new TokenResponseVO()
                .accessToken(createToken(Optional.empty(), Optional.of(clientId), Map.of(), Map.of()))
                .expiresIn(3600)
                .scope(I_SHARE_SCOPE).tokenType("Bearer");
        log.debug("Successfully issued token for {}", clientId);
        return HttpResponse.ok(tokenResponseVO);
    }

    @Secured(SecurityRule.IS_AUTHENTICATED)
    @IShareJWT
    @Override
    public HttpResponse<TrustedListResponseVO> getTrustedList() {
        List<TrustedCAVO> trustedCAs = partiesRepo.getTrustedCAs();
        log.debug("Returning trusted CAs {}", trustedCAs);
        return HttpResponse.ok(new TrustedListResponseVO().trustedListToken(
                createToken(securityService.getAuthentication().map(Principal::getName),
                        Optional.empty(),
                        Map.of("trusted_list", trustedCAs), Map.of())));
    }

    private String createToken(Optional<String> aud, Optional<String> clientId, Map<String, List<?>>
            additionalClaims, Map<String, Map> mapClaim) {
        Map<String, Object> header = Map.of("x5c", certificateMapper.getCertificatesWithoutHeaders(satelliteProperties.getCertificate()));

        Algorithm signingAlgo = Algorithm.RSA256(
                (RSAPrivateKey) certificateMapper.getPrivateKey(satelliteProperties.getKey()));

        JWTCreator.Builder jwtBuilder = JWT.create()
                .withAudience(satelliteProperties.getId())
                .withIssuer(satelliteProperties.getId())
                .withSubject(satelliteProperties.getId())
                .withClaim("jti", UUID.randomUUID().toString())
                .withNotBefore(Clock.systemUTC().instant())
                .withExpiresAt(Clock.systemUTC().instant().plus(Duration.of(30, ChronoUnit.MINUTES)))
                .withArrayClaim("scope", new String[]{I_SHARE_SCOPE})
                .withHeader(header);
        aud.ifPresent(jwtBuilder::withAudience);
        clientId.ifPresent(ci -> jwtBuilder.withClaim("client_id", ci));
        if (!additionalClaims.isEmpty()) {
            additionalClaims.entrySet().forEach(entry ->
                    jwtBuilder.withClaim(entry.getKey(),
                            entry.getValue().stream().map(v -> OBJECT_MAPPER.convertValue(v, Map.class))
                                    .collect(Collectors.toList())));
        }
        if (!mapClaim.isEmpty()) {
            mapClaim.entrySet().forEach(entry -> jwtBuilder.withClaim(entry.getKey(), entry.getValue()));
        }

        return jwtBuilder.sign(signingAlgo);

    }


}
