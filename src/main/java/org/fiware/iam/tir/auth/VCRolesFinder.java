package org.fiware.iam.tir.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.DefaultRolesFinder;
import io.micronaut.security.token.config.TokenConfiguration;
import jakarta.inject.Singleton;
import org.fiware.iam.common.configuration.GeneralProperties;
import org.fiware.iam.common.model.Role;
import org.fiware.iam.common.model.VCData;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Provides functionality to resolve roles for a given service
 * based on the roles in VC
 */
@Singleton
@Replaces(DefaultRolesFinder.class)
public class VCRolesFinder extends DefaultRolesFinder {
    private static final String VC_KEY = "vc";

    private final ObjectMapper objectMapper;
    private final GeneralProperties generalProperties;

    public VCRolesFinder(TokenConfiguration tokenConfiguration, ObjectMapper objectMapper,
                         GeneralProperties generalProperties) {
        super(tokenConfiguration);
        this.objectMapper = objectMapper;
        this.generalProperties = generalProperties;
    }

    /**
     * Resolves and returns the roles for a given service
     *
     * @param attributes JWT payload
     * @return List of roles
     */
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
            Set<Role> roles = vcData.getCredentialSubject().getRoles();
            if (roles.stream().anyMatch(role -> role.getTarget().equals(generalProperties.getRoleTarget()))) {
                return roles;
            } else {
                throw new RuntimeException("Given role cannot be granted to the configured service");
            }
        } else {
            throw new RuntimeException("VC not found");
        }
    }
}
