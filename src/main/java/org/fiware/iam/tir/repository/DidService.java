package org.fiware.iam.tir.repository;

import org.fiware.iam.did.model.DIDDocumentVO;

import java.util.Optional;

/**
 * Handle retrieval of information bound to a DID
 */
public interface DidService {
    /**
     * @param did
     * @return Return the mapped did.json that was referenced by the input did
     */
    Optional<DIDDocumentVO> retrieveDidDocument(String did);

    /**
     * @param didDocument The did document holding possible verification methods
     * @return Base64 Encoded X.509 certificate if one was referenced in the verification methods
     */
    Optional<String> getCertificate(DIDDocumentVO didDocument);
}
