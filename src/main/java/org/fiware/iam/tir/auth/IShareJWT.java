package org.fiware.iam.tir.auth;

import java.lang.annotation.*;

/**
 * Annotation to force requiring a iShare formatted JWT token
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface IShareJWT {
}