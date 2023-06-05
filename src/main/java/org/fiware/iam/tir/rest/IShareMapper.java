package org.fiware.iam.tir.rest;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.satellite.model.AdherenceVO;
import org.fiware.iam.satellite.model.CertificateVO;
import org.fiware.iam.satellite.model.PartyVO;
import org.fiware.iam.tir.auth.CertificateMapper;
import org.fiware.iam.tir.auth.JWTService;
import org.fiware.iam.tir.configuration.Party;

import javax.inject.Singleton;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * Maps internal models into objects of the iShare domain
 */
@Singleton
@RequiredArgsConstructor
@Slf4j
public class IShareMapper {

    private final CertificateMapper certificateMapper;

    public PartyVO partyToPartyVO(Party party) {
        return new PartyVO()
                .partyId(party.id())
                .partyName(party.name())
                .adherence(new AdherenceVO().status(party.status()))
                .certificates(toCertificateVO(getClientCertificate(party)));
    }

    private X509Certificate getClientCertificate(Party party) {
        return certificateMapper.getCertificates(party.crt()).get(0);
    }

    private List<CertificateVO> toCertificateVO(X509Certificate certificate) {
        try {
            return List.of(new CertificateVO()
                    .certificateType(certificate.getType())
                    .enabledFrom(certificate.getNotBefore().toString())
                    .subjectName(certificate.getSubjectX500Principal().getName())
                    .x5c(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                    .x5tHashS256(certificateMapper.getThumbprint(certificate)));
        } catch (CertificateEncodingException e) {
            log.warn("Was not able to encode certificate", e);
            return List.of();
        }
    }
}
