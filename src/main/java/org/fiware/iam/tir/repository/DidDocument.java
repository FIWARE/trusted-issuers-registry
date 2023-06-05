package org.fiware.iam.tir.repository;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class DidDocument {

	private List<Object> assertionMethod;
	private List<Object> authentication;
	@JsonProperty("@context")
	private List<String> context;
	private String id;
	private List<VerificationMethod> verificationMethod;
}
