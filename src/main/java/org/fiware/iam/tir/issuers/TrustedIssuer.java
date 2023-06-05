package org.fiware.iam.tir.issuers;

import io.github.wistefan.mapping.annotations.AttributeGetter;
import io.github.wistefan.mapping.annotations.AttributeSetter;
import io.github.wistefan.mapping.annotations.AttributeType;
import io.github.wistefan.mapping.annotations.MappingEnabled;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import org.fiware.iam.common.domain.EntityWithId;


/**
 * Minimalistic representation of a VC https://www.w3.org/TR/vc-data-model/
 */
@EqualsAndHashCode(callSuper = true)
@MappingEnabled(entityType = TrustedIssuer.TYPE_TRUSTED_ISSUER)
public class TrustedIssuer extends EntityWithId {

    public static final String TYPE_TRUSTED_ISSUER = "TrustedIssuer";

    @Getter(onMethod = @__({@AttributeGetter(value = AttributeType.PROPERTY, targetName = "issuer")}))
    @Setter(onMethod = @__({@AttributeSetter(value = AttributeType.PROPERTY, targetName = "issuer")}))
    private String issuer;

    public TrustedIssuer(String id) {
        super(TYPE_TRUSTED_ISSUER, id);
    }

}
