package org.fiware.iam.common.exception;

/**
 * Details of an error provided to the caller.
 */
public record ErrorDetails(String code, String reason, String message, String status, String referenceError) {
}