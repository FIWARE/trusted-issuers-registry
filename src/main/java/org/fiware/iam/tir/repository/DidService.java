package org.fiware.iam.tir.repository;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientException;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import lombok.RequiredArgsConstructor;

import javax.inject.Singleton;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Optional;

/**
 * Handle resolving DID's according to https://w3c-ccg.github.io/did-method-web/#create-register
 */
@RequiredArgsConstructor
@Singleton
public class DidService {

    private final HttpClient httpClient;

    /**
     * @param did
     * @return Return the mapped did.json that was referenced by the input did
     */
    public Optional<DidDocument> retrieveDidDocument(String did) {
        String documentPath = getDIDDocumentPath(did);
        HttpResponse<DidDocument> res = httpClient.toBlocking()
                .exchange(documentPath, DidDocument.class);
        return Optional.ofNullable(res).filter(response -> response.status() == HttpStatus.OK).map(HttpResponse::body);
    }

    /**
     * @param didDocument The did document holding possible verification methods
     * @return Base64 Encoded X.509 certificate if one was referenced in the verification methods
     */
    public Optional<String> getCertificate(DidDocument didDocument) {
        try {
            return Optional
                    .ofNullable(didDocument.getVerificationMethod())
                    .orElseGet(ArrayList::new)
                    .stream()
                    .map(VerificationMethod::getPublicKeyJwk)
                    .filter(Objects::nonNull)
                    .map(JWK::getX5u)
                    .filter(Objects::nonNull)
                    .map(certificateAddress -> httpClient.toBlocking().retrieve(certificateAddress))
                    .findFirst();
        } catch (HttpClientException e) {
            throw new IllegalArgumentException("Could not retrieve certificate for did %s".formatted(didDocument.getId()), e);
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
