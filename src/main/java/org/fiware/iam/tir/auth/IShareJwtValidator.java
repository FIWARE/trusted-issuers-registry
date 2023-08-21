package org.fiware.iam.tir.auth;

import com.auth0.jwt.interfaces.DecodedJWT;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtAuthenticationFactory;
import io.micronaut.security.token.jwt.validator.JwtTokenValidator;
import io.micronaut.security.token.jwt.validator.JwtValidator;
import io.micronaut.web.router.MethodBasedRouteMatch;
import jakarta.inject.Singleton;
import org.fiware.iam.tir.repository.PartiesRepo;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

import java.util.Collection;

@Singleton
@Replaces(JwtTokenValidator.class)
public class IShareJwtValidator extends JwtTokenValidator {

	/**
	 * Attribute used by Micronaut to hold the route mapping info
	 */
	private static final String MICRONAUT_HTTP_ROUTE_INFO_ATTRIBUTE = "micronaut.http.route.info";
	private final JWTService jwtService;

	public IShareJwtValidator(
			Collection<SignatureConfiguration> signatureConfigurations,
			Collection<EncryptionConfiguration> encryptionConfigurations,
			Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
			JwtAuthenticationFactory jwtAuthenticationFactory,
			JWTService jwtService) {
		super(signatureConfigurations, encryptionConfigurations, genericJwtClaimsValidators, jwtAuthenticationFactory);
		this.jwtService = jwtService;
	}

	public IShareJwtValidator(JwtValidator validator,
			JwtAuthenticationFactory jwtAuthenticationFactory,
			JWTService jwtService) {
		super(validator, jwtAuthenticationFactory);
		this.jwtService = jwtService;
	}

	@Override
	public Publisher<Authentication> validateToken(String token, HttpRequest<?> request) {
		if(isIShareTokenRequired(request)) {
			try {
				DecodedJWT decodedJWT = jwtService.validateJWT(token);
				return Flux.just(Authentication.build(decodedJWT.getClaim("client_id").asString()));
			} catch (Exception e) {
				return Flux.empty();
			}
		}else{
			return super.validateToken(token,request);
		}
	}

	private boolean isIShareTokenRequired(HttpRequest<?> request){
		return request
				.getAttribute(MICRONAUT_HTTP_ROUTE_INFO_ATTRIBUTE)
				.filter(MethodBasedRouteMatch.class::isInstance)
				.map(MethodBasedRouteMatch.class::cast)
				.filter(e -> e.hasAnnotation(IShareJWT.class))
				.isPresent();
	}
}
