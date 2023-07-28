package org.fiware.iam.tir.repository;

import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientException;
import lombok.RequiredArgsConstructor;
import org.fiware.iam.did.model.DIDDocumentVO;
import org.fiware.iam.did.model.DIDDocumentVerificationMethodInnerVO;
import org.fiware.iam.did.model.JsonWebKey2020VerificationMethodVO;
import org.fiware.iam.did.model.RsaVerificationKey2018VerificationMethodVO;

import javax.inject.Singleton;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Optional;

/**
 * Handle resolving DID's according to [DID:Web]{https://w3c-ccg.github.io/did-method-web/#create-register}
 */
@RequiredArgsConstructor
@Singleton
public class DidWebService implements DidService {

    private final HttpClient httpClient;

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<DIDDocumentVO> retrieveDidDocument(String did) {
        String documentPath = getDIDDocumentPath(did);
        HttpResponse<DIDDocumentVO> res = httpClient.toBlocking()
                .exchange(documentPath, DIDDocumentVO.class);
        return Optional.ofNullable(res).filter(response -> response.status() == HttpStatus.OK).map(HttpResponse::body);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<String> getCertificate(DIDDocumentVO didDocument) {
        return Optional
                .ofNullable(didDocument.getVerificationMethod())
                .orElseGet(ArrayList::new)
                .stream()
                .map(this::retrieveCertificate)
                .flatMap(Optional::stream)
                .findFirst();
    }

    private Optional<String> retrieveCertificate(DIDDocumentVerificationMethodInnerVO verificationMethodVO) {
        return Optional.of(verificationMethodVO).map(method -> {
                    if (verificationMethodVO instanceof JsonWebKey2020VerificationMethodVO) {
                        return ((JsonWebKey2020VerificationMethodVO) verificationMethodVO).getPublicKeyJwk();
                    } else if (verificationMethodVO instanceof RsaVerificationKey2018VerificationMethodVO) {
                        return ((RsaVerificationKey2018VerificationMethodVO) verificationMethodVO).getPublicKeyJwk();
                    } else {
                        throw new IllegalArgumentException("Verification method type %s not supported.".formatted(verificationMethodVO.getType()));
                    }
                })
                .map(publicKeyJwk -> {
                    //TODO create cert string from other fields (eg n&e)
                    if (StringUtils.isNotEmpty(publicKeyJwk.getX5u())) {
                        return downloadCertificate(publicKeyJwk.getX5u());
                    } else if (publicKeyJwk.getX5c() != null && publicKeyJwk.getX5c().size() > 0) {
                        return downloadCertificate(publicKeyJwk.getX5c().get(0));
                    } else {
                        throw new IllegalArgumentException("Could not retrieve certificate for controller %s and public key JWK %s".formatted(verificationMethodVO.getType(), publicKeyJwk));
                    }
                });
    }

    private String downloadCertificate(String certificateAddress) {
        try {
            return httpClient.toBlocking().retrieve(certificateAddress);
        } catch (HttpClientException e) {
            throw new IllegalArgumentException("Could not retrieve certificate from %s".formatted(certificateAddress), e);
        }
    }

    private String getDIDDocumentPath(String did) {
        String[] didParts = did.split(":");
        if (didParts.length < 3) {
            throw new IllegalArgumentException("Did must be at least 3 segments big.");
        }
        // Decode optional port usage
        didParts[2] = URLDecoder.decode(didParts[2], StandardCharsets.UTF_8);

        if (!didParts[1].equals("web")) {
            throw new IllegalArgumentException("Only did web is supported.");
        }

        if (didParts.length == 3) {
            // standard well-known path
            return String.format("https://%s/.well-known/did.json", didParts[2]);
        }
        String documentPath = "https://" + didParts[2];

        for (int i = 3; i < didParts.length; i++) {
            documentPath += "/" + didParts[i];
        }
        documentPath += "/did.json";
        return documentPath;

    }
}
