package org.fiware.iam.common.model;

import lombok.Data;

import java.util.Set;

@Data
public class VCClaims {
	private Set<Role> roles;
}
