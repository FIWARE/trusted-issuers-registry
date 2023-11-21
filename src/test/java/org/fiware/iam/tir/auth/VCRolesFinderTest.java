package org.fiware.iam.tir.auth;

import io.micronaut.context.annotation.Property;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

@MicronautTest
public class VCRolesFinderTest {

    @Inject
    private VCRolesFinder rolesFinder;

    @Test
    @Property(name = "allowedVCTypes", value = "MyType,OtherType")
    public void testRolesResolveWithAllowedVCTypes() {
        Map<String, Object> tokenPayload = Map.of(
                "vc", Map.of(
                        "type", List.of("MyType"),
                        "credentialSubject", Map.of(
                                "roles", List.of(Map.of(
                                        "names", List.of("CREATE_ISSUER")
                                ))
                        )
                )
        );

        Assertions.assertEquals(List.of("CREATE_ISSUER"), rolesFinder.resolveRoles(tokenPayload));
    }

    @Test
    @Property(name = "allowedVCTypes", value = "AnyType")
    public void testRolesResolveWithNotAllowedVCTypes() {
        Map<String, Object> tokenPayload = Map.of(
                "vc", Map.of(
                        "type", List.of("NotAllowedType"),
                        "credentialSubject", Map.of(
                                "roles", List.of(Map.of(
                                        "names", List.of("CREATE_ISSUER")
                                ))
                        )
                )
        );

        Assertions.assertEquals(List.of(), rolesFinder.resolveRoles(tokenPayload));
    }

}
