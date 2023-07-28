package org.fiware.iam.tir.configuration;

import org.fiware.iam.did.model.DIDDocumentVO;

public record Party(String id, String did, String name, String status, String crt, DIDDocumentVO didDocument) {
}
