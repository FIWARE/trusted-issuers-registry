package org.fiware.iam.tir;

import io.micronaut.context.annotation.Factory;
import io.micronaut.runtime.Micronaut;

@Factory
public class Application {

	public static void main(String[] args) {
		Micronaut.run(Application.class, args);
	}


}
