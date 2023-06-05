package org.fiware.iam.tir.repository;

import lombok.Data;

@Data
public class JWK {

	private String alg;
	private String e;
	private String kid;
	private String kty;
	private String n;
	private String use;
	private String x5u;

}
