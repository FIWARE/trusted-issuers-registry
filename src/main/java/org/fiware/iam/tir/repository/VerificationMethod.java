package org.fiware.iam.tir.repository;

import lombok.Data;

@Data
public class VerificationMethod {

	private String controller;
	private String id;
	private String type;
	private JWK publicKeyJwk;
}
