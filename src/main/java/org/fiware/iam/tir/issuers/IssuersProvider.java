package org.fiware.iam.tir.issuers;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.common.repository.TrustedIssuersRepository;
import reactor.core.publisher.Mono;

import javax.inject.Singleton;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static java.util.Collections.emptyList;

/**
 * Provides access to the Trusted Issuers that are stored in the underlying persistence
 */
@Slf4j
@Singleton
@RequiredArgsConstructor
public class IssuersProvider {

    private final TrustedIssuersRepository trustedIssuersRepository;

    /**
     * @return The first 1000 Trusted issuers that are available
     */
    public List<TrustedIssuer> getAllTrustedIssuers() {
        Mono<List<TrustedIssuer>> entities = trustedIssuersRepository.findEntities(0, 1000, TrustedIssuer.TYPE_TRUSTED_ISSUER,
                TrustedIssuer.class);
        return Optional.ofNullable(entities.block(Duration.ofSeconds(30))).orElse(emptyList());
    }

}
