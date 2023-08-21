package org.fiware.iam.tir.rest;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.did.api.DidApi;
import org.fiware.iam.did.model.DIDDocumentVO;
import org.fiware.iam.tir.auth.IShareJWT;
import org.fiware.iam.tir.configuration.Party;
import org.fiware.iam.tir.repository.DidDocumentMapper;
import org.fiware.iam.tir.repository.PartiesRepo;

import java.time.LocalDate;
import java.util.Optional;

/**
 * Controller implementing a subset of the [DID Registry as defined by EBSI](https://api-pilot.ebsi.eu/docs/apis/did-registry/v4#/)
 * as currently required by the [VCVerifier](https://github.com/FIWARE/VCVerifier) to check trusted participants of a dataspace.
 */
@RequiredArgsConstructor
@Slf4j
@Controller("${general.basepath:/}")
@Secured(SecurityRule.IS_AUTHENTICATED)
public class DidRegistry implements DidApi {

    private final DidDocumentMapper didDocumentMapper;
    private final PartiesRepo partiesRepo;

    /**
     * Gets the DID document corresponding to the DID.
     *
     * @param did The DID of the entity in question
     * @return The DID Document if the DID belongs to a trusted participant
     */
    @Override
    public HttpResponse<DIDDocumentVO> getDIDDocument(String did, @Nullable LocalDate validAt) {
        return partiesRepo
                .getPartyByDID(did)
                .flatMap(this::retrieveDidDocumentOfTrustedParticipant)
                .map(HttpResponse::ok)
                .orElse(HttpResponse.notFound());
    }

    private Optional<DIDDocumentVO> retrieveDidDocumentOfTrustedParticipant(Party trustedParty) {
        return Optional.ofNullable(trustedParty.didDocument()).or(() -> didDocumentMapper.map(trustedParty));
    }


}
