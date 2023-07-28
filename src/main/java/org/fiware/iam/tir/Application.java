package org.fiware.iam.tir;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.event.BeanCreatedEvent;
import io.micronaut.context.event.BeanCreatedEventListener;
import io.micronaut.runtime.Micronaut;
import jakarta.inject.Singleton;

@Factory
public class Application {

	public static void main(String[] args) {
		Micronaut.run(Application.class, args);
	}


	/**
	 * Allow unknown properties to make working with the generated DIDDocuments more convenient
	 */
	@Singleton
	static class ObjectMapperBeanEventListener implements BeanCreatedEventListener<ObjectMapper> {

		@Override
		public ObjectMapper onCreated(BeanCreatedEvent<ObjectMapper> event) {
			final ObjectMapper mapper = event.getBean();
			mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
			return mapper;
		}
	}
}
