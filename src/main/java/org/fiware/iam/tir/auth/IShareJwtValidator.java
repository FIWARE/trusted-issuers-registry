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
import jakarta.inject.Singleton;
import org.fiware.iam.tir.repository.PartiesRepo;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

import java.util.Collection;

@Singleton
@Replaces(JwtTokenValidator.class)
public class IShareJwtValidator extends JwtTokenValidator {

	private final JWTService jwtService;
	private final PartiesRepo partiesRepo;

	public IShareJwtValidator(
			Collection<SignatureConfiguration> signatureConfigurations,
			Collection<EncryptionConfiguration> encryptionConfigurations,
			Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
			JwtAuthenticationFactory jwtAuthenticationFactory,
			JWTService jwtService, PartiesRepo partiesRepo) {
		super(signatureConfigurations, encryptionConfigurations, genericJwtClaimsValidators, jwtAuthenticationFactory);
		this.jwtService = jwtService;
		this.partiesRepo = partiesRepo;
	}

	public IShareJwtValidator(JwtValidator validator,
			JwtAuthenticationFactory jwtAuthenticationFactory,
			JWTService jwtService, PartiesRepo partiesRepo) {
		super(validator, jwtAuthenticationFactory);
		this.jwtService = jwtService;
		this.partiesRepo = partiesRepo;
	}

	@Override
	public Publisher<Authentication> validateToken(String token, HttpRequest<?> request) {
		try {
			DecodedJWT decodedJWT = jwtService.validateJWT(token);
			return Flux.just(Authentication.build(decodedJWT.getClaim("client_id").asString()));
		} catch (Exception e) {
			return Flux.empty();
		}
	}
}
