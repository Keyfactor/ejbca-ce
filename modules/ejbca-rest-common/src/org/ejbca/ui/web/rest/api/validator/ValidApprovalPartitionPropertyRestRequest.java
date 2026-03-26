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

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import org.ejbca.ui.web.rest.api.io.request.ApprovalPartitionPropertyRestRequest;
import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidApprovalPartitionPropertyRestRequest.Validator.class})
@Documented
public @interface ValidApprovalPartitionPropertyRestRequest {
    String message() default "{ValidApprovalPartitionPropertyRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};


    class Validator implements ConstraintValidator<ValidApprovalPartitionPropertyRestRequest, ApprovalPartitionPropertyRestRequest> {

        @Override
        public void initialize(ValidApprovalPartitionPropertyRestRequest constraintAnnotation) {
        }

        @Override
        public boolean isValid(ApprovalPartitionPropertyRestRequest request, ConstraintValidatorContext constraintValidatorContext) {
            if (request == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidApprovalPartitionPropertyRestRequest.invalid.null}");
                return false;
            }
            if (request.getType() == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidApprovalPartitionPropertyRestRequest.invalid.type.null}");
                return false;
            }
            String value = request.getValue();
            if (value != null) {
                switch (request.getType()) {
                    case "String", "RadioButton", "MultiLineString", "UrlString":
                        break;
                    case "Integer":
                        try {
                            Integer.parseInt(value);
                        } catch (NumberFormatException e) {
                            ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidApprovalPartitionPropertyRestRequest.invalid.value.notAnInteger}",
                                    request.getValue(), request.getLabel());
                            return false;
                        }
                        break;
                    case "Boolean":
                        if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                            ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidApprovalPartitionPropertyRestRequest.invalid.value.notABoolean}",
                                    request.getValue(), request.getLabel());
                            return false;
                        }
                        break;
                    case "Long":
                        try {
                            Long.parseLong(value);
                        } catch (NumberFormatException e) {
                            ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidApprovalPartitionPropertyRestRequest.invalid.value.notALong}",
                                    request.getValue(), request.getLabel());
                            return false;
                        }
                        break;
                    default: 
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidApprovalPartitionPropertyRestRequest.invalid.type.unknown}", request.getType());
                        return false;
                }
            }
            return true;
        }
    }
}
