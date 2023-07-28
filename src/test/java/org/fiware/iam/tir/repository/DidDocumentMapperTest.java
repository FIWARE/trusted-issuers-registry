package org.fiware.iam.tir.repository;

import org.fiware.iam.did.model.DIDDocumentVO;
import org.fiware.iam.did.model.JWKVO;
import org.fiware.iam.did.model.RsaVerificationKey2018VerificationMethodVO;
import org.fiware.iam.tir.auth.CertificateMapper;
import org.fiware.iam.tir.configuration.Party;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class DidDocumentMapperTest {


    private static final String TEST_CERT = """
            MIIFCzCCA/OgAwIBAgISA9RPNlojVGB9w38q7HOun46eMA0GCSqGSIb3DQEBCwUA
            MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
            EwJSMzAeFw0yMzA3MjAxMTE4MTJaFw0yMzEwMTgxMTE4MTFaMCkxJzAlBgNVBAMT
            HnBhY2tldGRlbGl2ZXJ5LmRzYmEuZml3YXJlLmRldjCCASIwDQYJKoZIhvcNAQEB
            BQADggEPADCCAQoCggEBAJp8X9Y5nRNb6uRmcwP6jlTRxOtE+a249Y+UOnOlz8gm
            aQMb+xucNJD2Sx1H8PXTgWXvQ7T5uYBfXi8R2KGJEq5zXRmKlg9ruLGprff09Jqi
            bb9/4PxYXthHBRE+S6CizqpNEPVOGhe+RymjCpCUmyoKIuXb5tkUV4v2wgXU4Ju7
            dSPxNjmvzjbu7dMAzZryzuARNXBz9z2dqGQeYpATCseCHw/Jg1rv53uS3hTvd1BA
            KYnUqU5/yJvyIXMl0WmavKR6gt/8llS+Hvbqo5ekewpCiFNsFZOHk20HJ49aND7X
            ePFkCqYmZ4ILvX885QWGmFAQjhg82kNKa454vf2g3FUCAwEAAaOCAiIwggIeMA4G
            A1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYD
            VR0TAQH/BAIwADAdBgNVHQ4EFgQUDWK28U5FUpSco1KlVlGC+ZcYD3wwHwYDVR0j
            BBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsG
            AQUFBzABhhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6
            Ly9yMy5pLmxlbmNyLm9yZy8wKQYDVR0RBCIwIIIecGFja2V0ZGVsaXZlcnkuZHNi
            YS5maXdhcmUuZGV2MBMGA1UdIAQMMAowCAYGZ4EMAQIBMIIBBgYKKwYBBAHWeQIE
            AgSB9wSB9ADyAHcAtz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAGJ
            czyCSgAABAMASDBGAiEAnzug9Q6xfyRr7foI3l7+8MpTchI7iI/trzWY8ossJjcC
            IQCxS+ncerHIzXbioGQZ9d9guWi5+9mnc3GQxzW/7GHSRAB3AHoyjFTYty22IOo4
            4FIe6YQWcDIThU070ivBOlejUutSAAABiXM8gmEAAAQDAEgwRgIhAJAsWg+UcOTT
            s5sqxWpiWvCkZKVVDAHTQvEjy0zAfBT5AiEAmxRCME2imbqQZC9GRaepjCT8Nd26
            dG7rK7CUy/hliVkwDQYJKoZIhvcNAQELBQADggEBACrmySsba5f5NGjYhZYNMnjD
            x6I9Dv6S9VFbu7COvdvZXvWUZjT0Yt6a2lnjykjpRosBYHz45lh0XDINXigOEEi8
            O7aQ0n4M9gYt4f/0H+DlXM/jgFpHdWXcYCNBtTg8gKlGjatN6PWvRmf2AbHSBuaq
            daAclDYszBoUoefpkmyRW8k2uCigSnM4RDGgDI+sAP5ZYKVbsBG/DJdpGFgcrQfy
            TFHtb+rFlwwf+ldV/BlDovwuTCDpo5FjXzcLPVvDCT8zAKlVdj4nUSdJRmKOU0j2
            DvyynIG6/by0cVPSUWJjpZRGc7j5cu7/K8QxfoUcnn2c5epdX6DH7hpfRbuh0zw=
            """;

    private DidDocumentMapper classUnderTest = new DidDocumentMapper(new CertificateMapper());

    @Test
    void mapRSA() {
        Optional<DIDDocumentVO> mappingResult = classUnderTest.map(new Party("id", "id", "id", "id", TEST_CERT, null));
        assertThat(mappingResult).isPresent();
        DIDDocumentVO didDocumentVO = mappingResult.get();

        assertThat(didDocumentVO.getId()).isEqualTo("id");
        assertThat(didDocumentVO.getVerificationMethod()).hasAtLeastOneElementOfType(RsaVerificationKey2018VerificationMethodVO.class);
        RsaVerificationKey2018VerificationMethodVO rsaVerification = (RsaVerificationKey2018VerificationMethodVO) didDocumentVO.getVerificationMethod().get(0);

        assertThat(rsaVerification.getId()).isEqualTo("id");

        JWKVO publicKey = rsaVerification.getPublicKeyJwk();
        assertThat(publicKey.getN()).isEqualTo("mnxf1jmdE1vq5GZzA/qOVNHE60T5rbj1j5Q6c6XPyCZpAxv7G5w0kPZLHUfw9dOBZe9DtPm5gF9eLxHYoYkSrnNdGYqWD2u4samt9/T0mqJtv3/g/Fhe2EcFET5LoKLOqk0Q9U4aF75HKaMKkJSbKgoi5dvm2RRXi/bCBdTgm7t1I/E2Oa/ONu7t0wDNmvLO4BE1cHP3PZ2oZB5ikBMKx4IfD8mDWu/ne5LeFO93UEApidSpTn/Im/IhcyXRaZq8pHqC3/yWVL4e9uqjl6R7CkKIU2wVk4eTbQcnj1o0Ptd48WQKpiZnggu9fzzlBYaYUBCOGDzaQ0prjni9/aDcVQ==");
        assertThat(publicKey.getE()).isEqualTo("AQAB");
    }
}