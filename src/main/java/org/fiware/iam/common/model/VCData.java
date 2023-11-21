package org.fiware.iam.common.model;

import lombok.Data;

import java.util.Set;

@Data
public class VCData {
	private Set<String> type;
	private VCClaims credentialSubject;
}
