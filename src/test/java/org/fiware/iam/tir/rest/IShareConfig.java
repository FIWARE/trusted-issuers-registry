package org.fiware.iam.tir.rest;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.SneakyThrows;
import org.fiware.iam.tir.auth.CertificateMapper;
import org.fiware.iam.tir.configuration.Party;

import java.security.KeyFactory;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import static org.fiware.iam.tir.rest.TestUtils.strip;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class IShareConfig {
    private String id;
    private String key;
    private String certificate;
    private String client_crt;
    private String rootca;

    private List<Party> parties;


    public List<X509Certificate> getCertificateChain() {
        return new CertificateMapper().getCertificates(certificate);
    }

    public List<String> getEncodedCertificateChain() {
        return getCertificateChain().stream().map(cert -> {
            try {
                return Base64.getEncoder().encodeToString(cert.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException(e);
            }
        }).collect(Collectors.toList());
    }

    @SneakyThrows
    public RSAPublicKey getPublicKey() {
        return (RSAPublicKey) getCertificateChain().get(0).getPublicKey();
    }

    @SneakyThrows
    public RSAPrivateKey getPrivateKey() {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(strip(key)), "RSA");
        return (RSAPrivateKey) kf.generatePrivate(keySpecPKCS8);
    }
}
