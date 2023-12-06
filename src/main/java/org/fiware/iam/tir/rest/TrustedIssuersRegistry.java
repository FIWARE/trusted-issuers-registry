package org.fiware.iam.tir.rest;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.tir.api.TirApi;
import org.fiware.iam.tir.issuers.IssuersProvider;
import org.fiware.iam.tir.issuers.TrustedIssuerMapper;
import org.fiware.iam.tir.model.IssuerVO;
import org.fiware.iam.tir.model.IssuersResponseVO;
import reactor.core.publisher.Mono;

import javax.validation.constraints.Max;
import javax.validation.constraints.Min;

@RequiredArgsConstructor
@Slf4j
abstract class TrustedIssuersRegistry implements TirApi {
    private final IssuersProvider issuersProvider;
    private final TrustedIssuerMapper mapper;

    @Override
    public Mono<HttpResponse<IssuerVO>> getIssuer(@NonNull String did) {
        return issuersProvider
                .getAllTrustedIssuers()
                .map(til -> til.stream()
                        .filter(trustedIssuer -> trustedIssuer != null && trustedIssuer.getIssuer() != null)
                        .filter(issuer -> issuer.getIssuer().equalsIgnoreCase(did))
                        .map(mapper::map)
                        .findAny()
                        .map(HttpResponse::ok)
                        .orElseGet(HttpResponse::notFound));
    }

    /**
     * Currently not possible to implement pagination since we only have an implicit order guarantee for the ngsi
     * backend. Therefore we would have to cache everything in this service.
     *
     * @param pageSize
     * @param pageAfter
     * @return
     */
    @Override
    public Mono<HttpResponse<IssuersResponseVO>> getIssuers(@Nullable @Min(1) @Max(100) Integer pageSize, @Nullable String pageAfter) {
        return issuersProvider.getAllTrustedIssuers()
                .map(mapper::map)
                .map(HttpResponse::ok);
    }
}
