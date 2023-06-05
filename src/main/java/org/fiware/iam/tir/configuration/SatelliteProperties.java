package org.fiware.iam.tir.configuration;

import io.micronaut.context.annotation.ConfigurationProperties;
import lombok.Data;

import java.util.List;

@ConfigurationProperties("satellite")
@Data
public class SatelliteProperties {
	private String id;
	private String key;
	private String certificate;
	private List<TrustedCA> trustedList;
	private List<Party> parties;


}
