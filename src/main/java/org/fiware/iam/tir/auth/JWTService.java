package org.fiware.iam.tir.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.inject.Singleton;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.tir.configuration.Party;
import org.fiware.iam.tir.configuration.SatelliteProperties;
import org.fiware.iam.tir.configuration.TrustedCA;
import org.fiware.iam.tir.repository.PartiesRepo;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Handles validation of JWT tokens with iShare specifics. Verifies that the tokens are issued by a trusted party
 */
@Slf4j
@RequiredArgsConstructor
@Singleton
public class JWTService {

    private final PartiesRepo partiesRepo;
    private final SatelliteProperties satelliteProperties;
    private final CertificateMapper certificateMapper;


    private void validateCertificateChain(List<String> certificates) {
        try {
            List<Certificate> mappedCertificates = certificates
                    .stream()
                    .map(certificateMapper::mapCertificate)
                    .collect(Collectors.toList());
            List<? extends Certificate> certificateChain = certificateMapper.getCertificateFactory().generateCertPath(mappedCertificates).getCertificates();

            for (int i = 0; i < certificateChain.size() - 1; i++) {
                certificateChain.get(i).verify(certificateChain.get(i + 1).getPublicKey());
            }
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException |
                 SignatureException e) {
            throw new IllegalArgumentException("Certificate chain could not be validated", e);
        }
    }


    /**
     * Validate and decode a JWT token build according to the iShare spec. Requires a PEM formatted certificate chain in the header claim
     *
     * @param jwtString
     * @return
     */
    public DecodedJWT validateJWT(String jwtString) {
        DecodedJWT decodedJWT = JWT.decode(jwtString);
        List<String> certs = decodedJWT.getHeaderClaim("x5c").asList(String.class);
        if (certs.size() != 3) {
            throw new IllegalArgumentException("Did not receive a full x5c chain.");
        }

        validateCertificateChain(certs);

        String clientCert = certs.get(0);
        String caCert = certs.get(2);
        try {
            JWT.require(Algorithm.RSA256(certificateMapper.getPublicKey(clientCert))).build().verify(jwtString);
        } catch (JWTVerificationException jwtVerificationException) {
            throw new IllegalArgumentException("Token not verified.", jwtVerificationException);
        }
        Optional<String> optionalTrustedCA = satelliteProperties.getTrustedList().stream()
                .map(TrustedCA::crt)
                .map(certificateMapper::stripCertificateOfPEMHeaders)
                .filter(caCert::equals)
                .findFirst();
        if (optionalTrustedCA.isEmpty()) {
            partiesRepo.getPartyById(decodedJWT.getClaim("iss").asString())
                    .map(Party::crt)
                    .map(certificateMapper::getCertificatesWithoutHeaders)
                    // get the client cert
                    .map(parsedCerts -> parsedCerts.get(0))
                    .filter(clientCert::equals)
                    .orElseThrow(() -> new IllegalArgumentException("No trusted CA and no trusted party found."));
        }

        return decodedJWT;
    }





}
