package org.fiware.iam.tir.repository;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class DidServiceTest {

    @Mock
    private HttpClient httpClient;

    @Mock
    private BlockingHttpClient blockingHttpClient;
    @InjectMocks
    private DidService classUnderTest;

    @BeforeEach
    void setUp() {
        when(httpClient.toBlocking()).thenReturn(blockingHttpClient);
    }


    @ParameterizedTest
    @MethodSource("didDocuments")
    void retrieveDidDocument(String did, String expectedUri, boolean errorExpected) {
        try {
            when(blockingHttpClient.exchange(eq(expectedUri), any())).thenReturn(HttpResponse.ok().body(new DidDocument()));
            assertThat(classUnderTest.retrieveDidDocument(did)).isPresent();
            if (errorExpected) {
                fail("Should have caused error");
            }
            verify(blockingHttpClient, times(1)).exchange(expectedUri, DidDocument.class);
        } catch (Exception e) {
            if (!errorExpected) {
                throw e;
            }
        }
    }

    private static Stream<Arguments> didDocuments() {
        List<Arguments> testCases = new ArrayList<>();
        testCases.add(Arguments.of("did:web:something.com", "https://something.com/.well-known/did.json", false));
        testCases.add(Arguments.of("did:web:something.com:customPath", "https://something.com/customPath/did.json", false));
        testCases.add(Arguments.of("did:web:something.com%3A1234:customPath", "https://something.com:1234/customPath/did.json", false));
        testCases.add(Arguments.of("did:notweb:something.com:customPath", "", true));
        return testCases.stream();
    }

    @ParameterizedTest
    @MethodSource("certificates")
    void getCertificate(DidDocument didDocument, String expectedUrl, boolean errorExpected, boolean resultExpected) {
        if(expectedUrl!= null){
            when(blockingHttpClient.retrieve(expectedUrl)).thenReturn("certificate");
        }else{
            when(blockingHttpClient.retrieve(anyString())).thenThrow(new HttpClientResponseException("Fail",HttpResponse.notFound()));
        }
        try {
            Optional<String> certificate = classUnderTest.getCertificate(didDocument);
            assertThat(certificate.isPresent()).isEqualTo(resultExpected);
            if (errorExpected) {
                fail("Should have caused error");
            }
        }catch (Exception e){
            if(!errorExpected){
                throw e;
            }
        }
    }

    private static Stream<Arguments> certificates() {
        List<Arguments> testCases = new ArrayList<>();
        testCases.add(Arguments.of(new DidDocument().setVerificationMethod(List.of(new VerificationMethod().setPublicKeyJwk(new JWK().setX5u("https://something.com/cert.crt")))), "https://something.com/cert.crt", false, true));
        testCases.add(Arguments.of(new DidDocument(), "", false, false));
        testCases.add(Arguments.of(new DidDocument().setVerificationMethod(List.of(new VerificationMethod())), "", false, false));
        testCases.add(Arguments.of(new DidDocument().setVerificationMethod(List.of(new VerificationMethod().setPublicKeyJwk(new JWK()))), "", false, false));
        testCases.add(Arguments.of(new DidDocument().setVerificationMethod(List.of(new VerificationMethod().setPublicKeyJwk(new JWK().setX5u("https://something.com/cert.crt")))), null, true, false));
        return testCases.stream();
    }

}