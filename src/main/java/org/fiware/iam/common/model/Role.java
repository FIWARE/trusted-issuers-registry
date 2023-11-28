package org.fiware.iam.common.model;

import lombok.Data;

import java.util.Set;

@Data
public class Role {
    private Set<String> names;
    private String target;
}
