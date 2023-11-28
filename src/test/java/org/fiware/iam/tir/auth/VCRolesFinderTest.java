package org.fiware.iam.tir.auth;

import io.micronaut.context.annotation.Property;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

@MicronautTest
@RequiredArgsConstructor
public class VCRolesFinderTest {
    private final VCRolesFinder rolesFinder;

    @Test
    @Property(name = "general.roleTarget", value = "did:key:myService")
    public void testRolesResolveWithMatchingService() {
        Map<String, Object> tokenPayload = Map.of(
                "vc", Map.of(
                        "credentialSubject", Map.of(
                                "roles", List.of(Map.of(
                                        "names", List.of("CREATE_ISSUER"),
                                        "target", "did:key:myService"
                                ))
                        )
                )
        );

        Assertions.assertEquals(List.of("CREATE_ISSUER"), rolesFinder.resolveRoles(tokenPayload));
    }

    @Test
    @Property(name = "general.roleTarget", value = "did:key:myService")
    public void testRolesResolveWithNonMatchingService() {
        Map<String, Object> tokenPayload = Map.of(
                "vc", Map.of(
                        "credentialSubject", Map.of(
                                "roles", List.of(Map.of(
                                        "names", List.of("CREATE_ISSUER"),
                                        "target", "did:key:otherService"
                                ))
                        )
                )
        );

        Assertions.assertEquals(List.of(), rolesFinder.resolveRoles(tokenPayload));
    }

}
