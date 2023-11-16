package org.fiware.iam.tir.rest;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.annotation.Controller;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.fiware.iam.tir.issuers.IssuersProvider;
import org.fiware.iam.tir.issuers.TrustedIssuerMapper;


/**
 * Implementation of the Trusted Issuers Registry API that requires the users to authenticate
 */
@Requires(property="general.trustedIssuersRegistry.authenticated", value="true")
@Controller("${general.basepath:/}")
@Secured(SecurityRule.IS_AUTHENTICATED)
public class AuthenticatedTrustedIssuersRegistry extends TrustedIssuersRegistry{
    public AuthenticatedTrustedIssuersRegistry(IssuersProvider issuersProvider, TrustedIssuerMapper mapper) {
        super(issuersProvider, mapper);
    }
}
