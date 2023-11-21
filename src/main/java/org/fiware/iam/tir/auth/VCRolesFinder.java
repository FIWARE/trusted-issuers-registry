package org.fiware.iam.tir.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Value;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.DefaultRolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;
import org.fiware.iam.common.model.Role;
import org.fiware.iam.common.model.VCData;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Singleton
@Replaces(DefaultRolesFinder.class)
public class VCRolesFinder extends DefaultRolesFinder {
    private static final String VC_KEY = "vc";

    @Value("${allowedVCTypes}")
    private Set<String> allowedVCTypes;

    private final ObjectMapper objectMapper;

    public VCRolesFinder(TokenConfiguration tokenConfiguration, ObjectMapper objectMapper) {
        super(tokenConfiguration);
        this.objectMapper = objectMapper;
    }

    @Override
    @NonNull
    public List<String> resolveRoles(@Nullable Map<String, Object> attributes) {
        try {
            Set<Role> roles = extractVCRoles(attributes);
            return roles.stream().map(Role::getNames).flatMap(Set::stream).toList();
        } catch (RuntimeException e) {
            return super.resolveRoles(attributes);
        }
    }

    private Set<Role> extractVCRoles(Map<String, Object> attributes) {
        if (attributes != null && attributes.containsKey(VC_KEY)) {
            VCData vcData = objectMapper.convertValue(attributes.get(VC_KEY), VCData.class);
            if (allowedVCTypes.containsAll(vcData.getType())) {
                return vcData.getCredentialSubject().getRoles();
            } else {
                throw new RuntimeException("Credential type is not allowed");
            }
        } else {
            throw new RuntimeException("VC not found");
        }
    }
}
