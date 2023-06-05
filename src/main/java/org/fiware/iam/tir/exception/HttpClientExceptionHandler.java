package org.fiware.iam.tir.exception;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.exceptions.HttpClientException;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import lombok.extern.slf4j.Slf4j;
import org.fiware.iam.common.exception.ErrorDetails;

import javax.inject.Singleton;

/**
 * General handler for all un-catched {@link  HttpClientException}. Translates them into a proper 503.
 */
@Produces
@Singleton
@Requires(classes = {HttpClientException.class, ExceptionHandler.class})
@Slf4j
public class HttpClientExceptionHandler implements ExceptionHandler<HttpClientException, HttpResponse<ErrorDetails>> {

	@Override
	public HttpResponse<ErrorDetails> handle(HttpRequest request, HttpClientException exception) {
		log.info("The context broker was not reachable. Request: {}, ClientException: {}.", request, exception);
		return HttpResponse.status(HttpStatus.BAD_GATEWAY).body(new ErrorDetails(HttpStatus.BAD_GATEWAY.toString(),
				HttpStatus.BAD_GATEWAY.getReason(),
				"Context broker is not reachable.",
				HttpStatus.BAD_GATEWAY.toString(),
				null));
	}
}
