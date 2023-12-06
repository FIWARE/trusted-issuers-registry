package org.fiware.iam.tir.repository;

import io.micronaut.http.annotation.Part;
import io.micronaut.scheduling.annotation.Scheduled;
import jakarta.inject.Singleton;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.did.model.DIDDocumentVO;
import org.fiware.iam.satellite.model.TrustedCAVO;
import org.fiware.iam.tir.auth.CertificateMapper;
import org.fiware.iam.tir.configuration.Party;
import org.fiware.iam.tir.configuration.SatelliteProperties;
import org.fiware.iam.tir.issuers.IssuersProvider;
import org.fiware.iam.tir.issuers.TrustedIssuer;
import reactor.core.publisher.Mono;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

@Slf4j
@Singleton
public class InMemoryPartiesRepo implements PartiesRepo {

    private final SatelliteProperties satelliteProperties;
    private final IssuersProvider issuersProvider;
    private final List<Party> parties;
    private final DidService didService;
    private final CertificateMapper certificateMapper;

    public InMemoryPartiesRepo(SatelliteProperties satelliteProperties, IssuersProvider issuersProvider, DidService didService, CertificateMapper certificateMapper) {
        this.parties = new ArrayList<>(satelliteProperties.getParties());
        this.satelliteProperties = satelliteProperties;
        this.issuersProvider = issuersProvider;
        this.didService = didService;
        this.certificateMapper = certificateMapper;
    }

    private Optional<TrustedCAVO> toTrustedCaVO(X509Certificate caCert) {

        try {
            String subject = caCert.getSubjectX500Principal().toString();
            String validity = isValid(caCert);
            String fingerprint = certificateMapper.getThumbprint(caCert);
            return Optional.of(new TrustedCAVO().status("granted").certificateFingerprint(fingerprint)
                    .validity(validity).subject(subject));
        } catch (CertificateEncodingException e) {
            log.warn("Was not able to get the fingerprint.");
        }
        return Optional.empty();
    }

    private String isValid(X509Certificate cert) {
        try {
            cert.checkValidity();
            return "valid";
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return "invalid";
        }
    }

    @Scheduled(fixedDelay = "15s")
    public void updateParties() {
        List<Party> updatedParties = new ArrayList<>(satelliteProperties.getParties());

        issuersProvider.getAllTrustedIssuers()
                .flatMap(til -> Mono.zip(til.stream().map(this::getPartyForIssuer).toList(), parties -> Arrays.stream(parties).toList()))
                .subscribe(partiesList -> {
                    for (Object partyObject : partiesList) {
                        if (partyObject instanceof Party party) {
                            updatedParties.add(party);
                        } else {
                            log.warn("Object {} is not a party.", partyObject);
                        }
                    }
                    parties.clear();
                    parties.addAll(updatedParties);
                });
    }


    private Mono<Party> getPartyForIssuer(TrustedIssuer trustedIssuer) {
        return didService.retrieveDidDocument(trustedIssuer.getIssuer())
                .filter(Optional::isPresent)
                .map(Optional::get)
                .flatMap(didDoc -> didService
                        .getCertificate(didDoc)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .map(cert -> new Party(didDoc.getId(), didDoc.getId(), didDoc.getId(), "Active", cert, didDoc))
                );
    }

    @Override
    public List<Party> getParties() {
        return parties;
    }

    @Override
    public List<TrustedCAVO> getTrustedCAs() {
        List<TrustedCAVO> trustedCAVOS = new ArrayList<>();

        satelliteProperties.getTrustedList().stream()
                .forEach(trustedCA -> toTrustedCaVO(certificateMapper.getCertificates(trustedCA.crt()).get(0)).ifPresent(
                        trustedCAVOS::add));

        return trustedCAVOS;
    }

    @Override
    public Optional<Party> getPartyById(String id) {
        return parties.stream().filter(party -> party.id().equals(id)).findFirst();
    }

    @Override
    public Optional<Party> getPartyByDID(String did) {
        return parties.stream().filter(party -> party.did().equals(did)).findFirst();
    }

    @Override
    public void addParty(Party party) {

    }
}
