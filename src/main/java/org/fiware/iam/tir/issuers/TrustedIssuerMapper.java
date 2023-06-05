package org.fiware.iam.tir.issuers;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.codec.digest.DigestUtils;
import org.fiware.iam.common.mapping.IdHelper;
import org.fiware.iam.tir.model.IssuerAttributeVO;
import org.fiware.iam.tir.model.IssuerEntryVO;
import org.fiware.iam.tir.model.IssuerVO;
import org.fiware.iam.tir.model.IssuersResponseVO;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "jsr330", uses = IdHelper.class)
public interface TrustedIssuerMapper {

    /**
     * Since no attributes are extracted at the moment, but the client implementation requires at least one field, some dummy value is added
     * TODO Check adapting the client impl
     */
    String STATIC_ATTRIBUTE_NAME = "type";
    String STATIC_ATTRIBUTE_VALUE = "attribute";

    ObjectMapper MAPPER = new ObjectMapper();

    default IssuerVO map(TrustedIssuer trustedIssuer) {
        return new IssuerVO()
                .did(trustedIssuer.getIssuer())
                .addAttributesItem(mapAttribute(STATIC_ATTRIBUTE_NAME, STATIC_ATTRIBUTE_VALUE));
    }

    default IssuersResponseVO map(List<TrustedIssuer> issuers) {
        IssuersResponseVO responseVO = new IssuersResponseVO();
        issuers.forEach(issuer -> responseVO.addItemsItem(new IssuerEntryVO().did(issuer.getIssuer())));
        responseVO.setPageSize(issuers.size());
        responseVO.setTotal(issuers.size());
        return responseVO;
    }

    private IssuerAttributeVO mapAttribute(String key, String value) {
        try {
            IssuerAttributeVO answer = new IssuerAttributeVO();
            ObjectNode attribute = JsonNodeFactory.instance.objectNode().put(key, value);
            MAPPER.getFactory().configure(JsonGenerator.Feature.ESCAPE_NON_ASCII, true);
            String attributeString = MAPPER.writeValueAsString(attribute);
            return answer.body(attributeString).hash(DigestUtils.sha256Hex(attributeString));
        } catch (JsonProcessingException jpe) {
            throw new IllegalArgumentException("Failed embedding issuer attributes", jpe);
        }
    }

}
