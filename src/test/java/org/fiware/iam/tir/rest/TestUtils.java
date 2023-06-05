package org.fiware.iam.tir.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import lombok.SneakyThrows;

import java.io.File;
import java.util.concurrent.Callable;

public abstract class TestUtils {
    public static String strip(String text){
        return text
                .replaceAll("\\n", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "");
    }

    @SneakyThrows
    public static IShareConfig readConfig(String name) {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        return mapper.readValue(new File("src/test/resources/clients/" + name), IShareConfig.class);
    }
}
