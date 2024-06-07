package org.fiware.iam.tir.repository;

import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import org.assertj.core.api.Assertions;
import org.fiware.iam.did.model.DIDDocumentVO;
import org.fiware.iam.tir.auth.CertificateMapper;
import org.fiware.iam.tir.configuration.Party;
import org.fiware.iam.tir.configuration.SatelliteProperties;
import org.fiware.iam.tir.issuers.IssuersProvider;
import org.fiware.iam.tir.issuers.TrustedIssuer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class InMemoryPartiesRepoTest {

	@Spy
	private SatelliteProperties satelliteProperties = spy(new SatelliteProperties().setParties(List.of()));
	@Mock
	private IssuersProvider issuersProvider;
	@Spy
	private List<Party> parties = spy(new ArrayList<>());
	@Mock
	private DidService didService;
	@Mock
	private CertificateMapper certificateMapper;

	@InjectMocks
	private InMemoryPartiesRepo classUnderTest;

	@Test
	void updateParties() throws Exception{
		var didDocument = new DIDDocumentVO().id("someId");

		when(issuersProvider.getAllTrustedIssuers()).thenReturn(Mono.just(List.of(new TrustedIssuer("someId").setIssuer("good"),new TrustedIssuer("someOtherId").setIssuer("failing"))));
		when(didService.retrieveDidDocument("good")).thenReturn(Mono.just(Optional.of(didDocument)));
		when(didService.retrieveDidDocument("failing")).thenReturn(Mono.error(new IllegalStateException()));
		when(didService.getCertificate(any())).thenReturn(Mono.just(Optional.of("cert")));
		classUnderTest.updateParties();
		Assertions.assertThat(classUnderTest.getParties()).hasSize(1);
		Assertions.assertThat(classUnderTest.getParties()).element(0).isEqualTo(new Party("someId","someId","someId","Active","cert",didDocument));

	}
}