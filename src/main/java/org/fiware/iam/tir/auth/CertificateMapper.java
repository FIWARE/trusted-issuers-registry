package org.fiware.iam.tir.auth;

import io.micronaut.context.exceptions.BeanInstantiationException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;

import javax.inject.Singleton;
import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Handles conversion between PEM formatted certificates/keys and what is needed in the iShare domain
 */
@Slf4j
@Singleton
public class CertificateMapper {

    private static final String CERTIFICATE_TYPE_X509 = "X.509";
    @Getter
    private final CertificateFactory certificateFactory;

    public CertificateMapper() {
        try {
            certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE_X509);
        } catch (CertificateException e) {
            throw new BeanInstantiationException("Error setting up the certificate factory", e);
        }
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );
    }

    /**
     * @param base64EncodedCertificate base64 encoded certificate without PEM headers
     * @return
     */
    public Certificate mapCertificate(String base64EncodedCertificate) {
        try {
            String extendedCertString = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----".formatted(base64EncodedCertificate);
            ByteArrayInputStream inputStream = new ByteArrayInputStream(extendedCertString.getBytes(StandardCharsets.UTF_8));
            return certificateFactory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Could not validate certificate: %s".formatted(base64EncodedCertificate), e);
        }
    }

    /**
     * @param base64EncodedCertificate
     * @return The public key of the given x.509 certificate
     */
    public RSAPublicKey getPublicKey(String base64EncodedCertificate) {
        return Optional.of(mapCertificate(base64EncodedCertificate))
                .filter(cert -> cert instanceof X509Certificate)
                .map(cert -> (X509Certificate) cert)
                .map(Certificate::getPublicKey)
                .filter(key -> key instanceof RSAPublicKey)
                .map(key -> (RSAPublicKey) key)
                .orElseThrow(() -> new IllegalArgumentException("Only RSA Keys are supported. Certificate:'%s'".formatted(base64EncodedCertificate)));
    }

    /**
     * @param crt String with Certificates in PEM Format with headers
     * @return Mapped certificates
     */
    public List<X509Certificate> getCertificates(String crt) {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
                crt.getBytes());
        try {
            return certificateFactory.generateCertificates(byteArrayInputStream)
                    .stream()
                    .filter(cert -> cert instanceof X509Certificate)
                    .map(cert -> (X509Certificate) cert)
                    .toList();
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * @param crt String with Certificates in PEM Format with headers
     * @return base64 encoded certificates without headers
     */
    public List<String> getCertificatesWithoutHeaders(String crt) {

        return getCertificates(crt).stream().map(cert -> {
                    try {
                        return cert.getEncoded();
                    } catch (CertificateEncodingException e) {
                        log.info("Was not able to get the encoded cert.");
                        return null;
                    }
                })
                .map(certBytes -> Base64.getEncoder().encodeToString(certBytes)).toList();
    }

    /**
     * @param cert
     * @return Hash of the certificate
     */
    public String getThumbprint(X509Certificate cert) throws CertificateEncodingException {
        MessageDigest sha256 = DigestUtils.getSha256Digest();
        return DatatypeConverter.printHexBinary(sha256.digest(cert.getEncoded()));
    }

    /**
     * @param cert
     * @return The handed certificate, without the PEM header/tail and without linebreaks
     */
    public String stripCertificateOfPEMHeaders(String cert) {
        return cert.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
    }

    /**
     * @param key Key in PEM format with headers
     * @return The mapped key
     */
    public PrivateKey getPrivateKey(String key) {


        String privateKeyPEM = key
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END RSA PRIVATE KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
