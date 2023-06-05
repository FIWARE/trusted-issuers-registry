package org.fiware.iam.tir.rest;

import org.fiware.iam.satellite.api.SatelliteApi;
import org.fiware.iam.satellite.model.PartiesResponseVO;
import org.fiware.iam.satellite.model.PartyResponseVO;
import org.fiware.iam.satellite.model.TokenResponseVO;
import org.fiware.iam.satellite.model.TrustedListResponseVO;

/** Test client for {@link SatelliteApi}. **/
@jakarta.annotation.Generated("org.openapitools.codegen.languages.MicronautCodegen")
@io.micronaut.http.client.annotation.Client("/")
public interface SatelliteApiTestClientFixed {

	@io.micronaut.http.annotation.Get("/parties")
	@io.micronaut.http.annotation.Consumes({ "application/json" })
	io.micronaut.http.HttpResponse<PartiesResponseVO> getParties(
			@io.micronaut.core.annotation.Nullable
			@io.micronaut.http.annotation.QueryValue(value = "eori")
			java.lang.String eori,
			@io.micronaut.core.annotation.Nullable
			@io.micronaut.http.annotation.QueryValue(value = "certificate_subject_name")
			java.lang.String certificateSubjectName);

	@io.micronaut.http.annotation.Get("/parties")
	@io.micronaut.http.annotation.Consumes({ "application/json" })
	io.micronaut.http.HttpResponse<PartiesResponseVO> getParties(
			@io.micronaut.core.annotation.Nullable
			@io.micronaut.http.annotation.Header(io.micronaut.http.HttpHeaders.AUTHORIZATION)
			java.lang.String authorization,
			@io.micronaut.core.annotation.Nullable
			@io.micronaut.http.annotation.QueryValue(value = "eori")
			java.lang.String eori,
			@io.micronaut.core.annotation.Nullable
			@io.micronaut.http.annotation.QueryValue(value = "certificate_subject_name")
			java.lang.String certificateSubjectName);
	@io.micronaut.http.annotation.Get("/party/{partyId}")
	@io.micronaut.http.annotation.Consumes({ "application/json" })
	io.micronaut.http.HttpResponse<PartyResponseVO> getPartyById(
			@io.micronaut.core.annotation.NonNull
			@io.micronaut.http.annotation.PathVariable(value = "partyId")
			java.lang.String partyId);

	@io.micronaut.http.annotation.Get("/party/{partyId}")
	@io.micronaut.http.annotation.Consumes({ "application/json" })
	io.micronaut.http.HttpResponse<PartyResponseVO> getPartyById(
			@io.micronaut.core.annotation.Nullable
			@io.micronaut.http.annotation.Header(io.micronaut.http.HttpHeaders.AUTHORIZATION)
			java.lang.String authorization,
			@io.micronaut.core.annotation.NonNull
			@io.micronaut.http.annotation.PathVariable(value = "partyId")
			java.lang.String partyId);
	@io.micronaut.http.annotation.Post("/token")
	@io.micronaut.http.annotation.Produces({ "application/x-www-form-urlencoded" })
	@io.micronaut.http.annotation.Consumes({ "application/json" })
	io.micronaut.http.HttpResponse<TokenResponseVO> getToken(
			@io.micronaut.core.annotation.Nullable
			java.lang.String grant_type,
			@io.micronaut.core.annotation.Nullable
			java.lang.String client_id,
			@io.micronaut.core.annotation.Nullable
			java.lang.String scope,
			@io.micronaut.core.annotation.Nullable
			java.lang.String client_assertion_type,
			@io.micronaut.core.annotation.Nullable
			java.lang.String client_assertion);

	@io.micronaut.http.annotation.Post("/token")
	@io.micronaut.http.annotation.Produces({ "application/x-www-form-urlencoded" })
	@io.micronaut.http.annotation.Consumes({ "application/json" })
	io.micronaut.http.HttpResponse<TokenResponseVO> getToken(
			@io.micronaut.core.annotation.Nullable
			@io.micronaut.http.annotation.Header(io.micronaut.http.HttpHeaders.AUTHORIZATION)
			java.lang.String authorization,
			@io.micronaut.core.annotation.Nullable
			java.lang.String grant_type,
			@io.micronaut.core.annotation.Nullable
			java.lang.String client_id,
			@io.micronaut.core.annotation.Nullable
			java.lang.String scope,
			@io.micronaut.core.annotation.Nullable
			java.lang.String client_assertion_type,
			@io.micronaut.core.annotation.Nullable
			java.lang.String client_assertion);
	@io.micronaut.http.annotation.Get("/trusted_list")
	@io.micronaut.http.annotation.Consumes({ "application/json" })
	io.micronaut.http.HttpResponse<TrustedListResponseVO> getTrustedList();

	@io.micronaut.http.annotation.Get("/trusted_list")
	@io.micronaut.http.annotation.Consumes({ "application/json" })
	io.micronaut.http.HttpResponse<TrustedListResponseVO> getTrustedList(
			@io.micronaut.core.annotation.Nullable
			@io.micronaut.http.annotation.Header(io.micronaut.http.HttpHeaders.AUTHORIZATION)
			java.lang.String authorization);
}
