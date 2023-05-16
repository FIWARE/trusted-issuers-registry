package org.fiware.gaiax.common.domain;

import lombok.EqualsAndHashCode;
import io.github.wistefan.mapping.annotations.MappingEnabled;

import java.util.List;

@EqualsAndHashCode(callSuper = true)
@MappingEnabled
public class PlaceRef extends RefEntity {

    public PlaceRef(String id) {
        super(id);
    }

    @Override
    public List<String> getReferencedTypes() {
        return List.of(getAtReferredType());
    }

}