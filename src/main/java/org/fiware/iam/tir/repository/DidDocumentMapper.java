package org.fiware.iam.tir.repository;

import com.nimbusds.jose.util.Base64;
import lombok.RequiredArgsConstructor;
import org.fiware.iam.did.model.DIDDocumentVO;
import org.fiware.iam.did.model.JWKVO;
import org.fiware.iam.did.model.RsaVerificationKey2018VerificationMethodVO;
import org.fiware.iam.tir.auth.CertificateMapper;
import org.fiware.iam.tir.configuration.Party;

import javax.inject.Singleton;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

@RequiredArgsConstructor
@Singleton
public class DidDocumentMapper {

    private final CertificateMapper certificateMapper;

    /**
     * Creates a DID Document for a party using an RSA Public Key
     * @param party
     * @return
     */
    public Optional<DIDDocumentVO> map(Party party) {
        String did = party.did();
        Certificate certificate = certificateMapper.mapCertificate(party.crt());
        PublicKey publicKey = certificate.getPublicKey();
        return Optional.of(publicKey)
                .filter(e -> e instanceof RSAPublicKey)
                .map(e -> (RSAPublicKey) e)
                .map(e -> new JWKVO()
                        .e(Base64.encode(e.getPublicExponent()).toString())
                        .n(Base64.encode(e.getModulus()).toString())
                        .alg(e.getAlgorithm())
                        .kty(e.getAlgorithm()))
                .map(jwk -> new DIDDocumentVO()
                        .id(did)
                        .addAtContextItem("https://www.w3.org/2018/credentials/v1")
                        .addAtContextItem("https://www.w3.org/ns/did/v1")
                        .addVerificationMethodItem(new RsaVerificationKey2018VerificationMethodVO()
                                .id(did)
                                .controller(did)
                                .publicKeyJwk(jwk)));
    }
}
