
/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.validator;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import org.ejbca.ui.web.rest.api.io.request.ProcessApprovalRestRequest;

/**
 * Validation annotation for input parameter with built-in validator. An input ProcessApprovalRestRequest is validated for:
 * <ul>
 *     <li>Not null.</li>
 * </ul>
 *
 * ProcessApprovalRestRequest's approve attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidProcessApprovalRestRequest.Validator.class})
@Documented
public @interface ValidProcessApprovalRestRequest {

    String message() default "{ValidProcessApprovalRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidProcessApprovalRestRequest, ProcessApprovalRestRequest> {

        @Override
        public void initialize(final ValidProcessApprovalRestRequest validProcessApprovalRestRequest) {
        }

        @Override
        public boolean isValid(final ProcessApprovalRestRequest processApprovalRestRequest, final ConstraintValidatorContext constraintValidatorContext) {
            if (processApprovalRestRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidProcessApprovalRestRequest.invalid.null}");
                return false;
            }
            if (processApprovalRestRequest.getApprove() == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidProcessApprovalRestRequest.invalid.approve.null}");
                return false;
            }
            return true;
        }
    }
}
