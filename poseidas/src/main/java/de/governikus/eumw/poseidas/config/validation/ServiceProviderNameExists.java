package de.governikus.eumw.poseidas.config.validation;



import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.validation.Constraint;
import javax.validation.Payload;


/**
 * This interface validates a field of a form model. It checks if a key pair with the name of th field value is
 * configured
 */
@Documented
@Constraint(validatedBy = ServiceProviderNameExistsValidator.class)
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ServiceProviderNameExists
{

  String message() default "This service provider does not exist!";

  Class<?>[] groups() default {};

  Class<? extends Payload>[] payload() default {};
}
