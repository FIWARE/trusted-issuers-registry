package org.fiware.iam.tir.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.fiware.iam.tir.configuration.Party;
import org.fiware.iam.tir.configuration.SatelliteProperties;
import org.fiware.iam.tir.configuration.TrustedCA;
import org.fiware.iam.tir.repository.PartiesRepo;
import org.fiware.iam.tir.rest.IShareConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.fiware.iam.tir.rest.TestUtils.readConfig;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class JWTServiceTest {

    @Mock
    private PartiesRepo partyRepo;

    @Mock
    private SatelliteProperties properties;

    @Spy
    private CertificateMapper certificateMapper = new CertificateMapper();

    @InjectMocks
    private JWTService classUnderTest;

    @ParameterizedTest
    @MethodSource("createJWTs")
    public void validateJWT(String description, String jwtToken, boolean success, String trustedCACrt, String partyCrt) {
        if (trustedCACrt != null) {
            when(properties.getTrustedList()).thenReturn(List.of(new TrustedCA("someCA", trustedCACrt)));
        }
        if (partyCrt != null) {
            when(partyRepo.getPartyById(anyString())).thenReturn(Optional.of(new Party("id", "did", "name", "status", partyCrt,null)));
        }
        try {
            classUnderTest.validateJWT(jwtToken);
            if (!success) {
                fail("Test should have failed: " + description);
            }
        } catch (Exception e) {
            if (success) {
                fail("Test should have succeeded:" + description, e);
            }
        }
    }


    private static Stream<Arguments> createJWTs() {
        List<Arguments> testCases = new ArrayList<>();
        testCases.add(Arguments.of("HappyPathTrustedCA", createSignedJWTClientToken("client_fiware.yaml"), true, TRUSTED_CA_FIWARE_CLIENT, null));
        testCases.add(Arguments.of("HappyPathClientIsKnownParty", createSignedJWTClientToken("client_fiware.yaml"), true, null, CLIENT_CRT));
        testCases.add(Arguments.of("NoCA", createSignedJWTClientToken("client_fiware.yaml"), false, null, null));
        testCases.add(Arguments.of("PartyNotRegistered", createSignedJWTClientToken("client_invalid.yaml"), false, null, CLIENT_CRT));
        testCases.add(Arguments.of("UnknownCA", createSignedJWTClientToken("client_unknownCA.yaml"), false, TRUSTED_CA_FIWARE_CLIENT, null));
        testCases.add(Arguments.of("ChainFaulty", createSignedJWTClientToken("client_frankenstein.yaml"), false, TRUSTED_CA_FIWARE_CLIENT, null));
        testCases.add(Arguments.of("ShortChain", createSignedJWTClientToken("client_noIntermediate.yaml"), false, TRUSTED_CA_FIWARE_CLIENT, null));
        return testCases.stream();
    }

    private static String createSignedJWTClientToken(String clientName) {
        IShareConfig clientConfig = readConfig(clientName);
        Instant now = Instant.now();
        return JWT.create()
                .withAudience("someAudience")
                .withIssuer(clientConfig.getId())
                .withSubject(clientConfig.getId())
                .withIssuedAt(now)
                .withNotBefore(now)
                .withClaim("client_id", "EU.EORI.FIWARECLIENT")
                .withExpiresAt(now.plusSeconds(30))
                .withHeader(Map.of("x5c", clientConfig.getEncodedCertificateChain()))
                .sign(Algorithm.RSA256(clientConfig.getPublicKey(), clientConfig.getPrivateKey()));
    }

    private static final String TRUSTED_CA_FIWARE_CLIENT = """
            -----BEGIN CERTIFICATE-----
              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
              YPTcYd127kzwmc+Kdjxrhh0WRvLPfrbEoJQStw==
              -----END CERTIFICATE-----            
            """;
    private static final String CLIENT_CRT = """
            -----BEGIN CERTIFICATE-----
              MIIGUTCCBDmgAwIBAgIJAMRilpUvUiv8MA0GCSqGSIb3DQEBCwUAMGcxCzAJBgNV
              BAYTAkRFMQ8wDQYDVQQIEwZCZXJsaW4xDzANBgNVBAoTBkZJV0FSRTEWMBQGA1UE
              AxQNRklXQVJFLUNBX1RMUzEeMBwGCSqGSIb3DQEJARYPdGVzdEBmaXdhcmUub3Jn
              MB4XDTIyMDQxNDEwMzI0N1oXDTI3MDQxMzEwMzI0N1owgaAxCzAJBgNVBAYTAkRF
              MQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJlcmxpbjEWMBQGA1UECgwNRklX
              QVJFIENsaWVudDEWMBQGA1UEAwwNRklXQVJFLUNsaWVudDEgMB4GCSqGSIb3DQEJ
              ARYRY2xpZW50QGZpd2FyZS5vcmcxHTAbBgNVBAUTFEVVLkVPUkkuRklXQVJFQ0xJ
              RU5UMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtsA7PjXAnqmgSShn
              5XyvtV5zmNHdWFbzaIFId4djoN5FfykDtLT28Qs6FW1qsDzwJtSf64mN1YZN0tv3
              B9wV9olyc9dnzZ40Sj76ivWZQz28yKGjryTMQe9p22kEBUba5lsbTM2+kQ5LWGl0
              NhNE0NJmNbGYRl0zeYOnTED8WJxhoy2lAmc66T2LNX1tUyvPtQTwiyXT+2p3HsIZ
              EuHus7o8lEezOy2hcOOPMOQuETSEzmoTsEHVV9AHdbRJjzR4CVlJN4ED9P81dOxV
              P732JWzDtUDmydCTQRiU0ryfFWFrhDAiSBfQTeQXMgcLuYKio4ePWntn+I2qxxCL
              5OY2ZvSUMV0qd38gKDECsgt9lm1On5WSTEScajyxwSq2NUo5KCG/bGnQXjyPQBmu
              Meah5Ce4Hw674SI6bUytEbM+6ik83qV8vBXDezHKIAXiZp5kgDrrnicEasLS0xKo
              RGT4g0cvSlDhWIaoocDbiVnmO2KDu6NgYoVwrTxs2yZt8Sp+Snn1so6LwG6YPzD0
              gteyMEpZ4riJR7uKrIXy6lRaBuAoMDgjJo/RcrMvB2hmsWZnC1m3jdWB8XVxNO3A
              2Ivy5a5J9ByLN/blcEfM2ChagX3LiwrmSjiwlgSQsuyVQn0hPmKZJAwl1oR2FiV5
              RQ12Rs2anN+UzgT2fiS2aidsA1UCAwEAAaOBxTCBwjAJBgNVHRMEAjAAMBEGCWCG
              SAGG+EIBAQQEAwIFoDAzBglghkgBhvhCAQ0EJhYkT3BlblNTTCBHZW5lcmF0ZWQg
              Q2xpZW50IENlcnRpZmljYXRlMB0GA1UdDgQWBBSeiF/x4gLKpg+WiUBsYHcXUU9y
              9zAfBgNVHSMEGDAWgBRdgB8aUXpL+TusztdqInP98QkHkTAOBgNVHQ8BAf8EBAMC
              BeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUA
              A4ICAQA2bdQehuX59Bng3mdlLnJS7CRuPePwxRYOxEJeQj8vRsFBNDF6xHIW1EMo
              h6aGH9quNaF/tkK/cd0t1yufCY5Pt9kIqOxhC64IwkixYwo/J2E5O9RQgKRUYmx6
              uMRwwkAITOdjPCEQ4j59DyMwXC8Y0fk0Cx87I9Sy+dmEU5WJDcGHU9OkUWGyLMre
              egVCePij8KD11n4JBNDiK2EyVTYFKN4QJLyTWlbeZd7X2jFTbxA41eg+Y2b3qm/8
              /7gVPxsazlaEhEgpsVbmnqMkabN4JKcFgpyrJrCmYNKMgNmC6UvaBCUExQbWxUbp
              SgLmjdhx3vyudg9E4XmpSaq+1qz+2DmUeNP7UBNIMxWRuOfLL976+Ylqr7NQlHb2
              7reZLh0MsKPzSIurf0Rx0X5ByYRWtgRZ0WkUQGeCgSrUhqN//0wkfsIp5xMFfxVH
              lL7bRqgTuJdFj7nd4TNBj9Dgc0uuTBM6MqLEENWFmmEMgcPT8PuJFGm/sWyWf5r3
              IiWKklGnXUqAPWTkWOAXV7EGoxc+5fYMw5AB+t7Dcatau4652CTR0/XVtj+ilfUu
              VWI09dDqRw2ml1whYTXbzUcorcQigufno+qgZff/1b//4GezUOwfERKnQ+lxbWK8
              gQ8q7jhH/vcx7jk7XF8qICTMSnT7VqT3ggnCDOn9KqlLVZmvWQ==
              -----END CERTIFICATE-----
            """;
}