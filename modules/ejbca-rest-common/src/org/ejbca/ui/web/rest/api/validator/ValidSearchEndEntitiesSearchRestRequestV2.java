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

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;

import org.ejbca.ui.web.rest.api.io.request.SearchEndEntitiesRestRequestV2;

@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSearchEndEntitiesSearchRestRequestV2.Validator.class})
@Documented
public @interface ValidSearchEndEntitiesSearchRestRequestV2 {
    String message() default "{ValidSearchEndEntitiesSearchRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidSearchEndEntitiesSearchRestRequestV2, SearchEndEntitiesRestRequestV2> {

        @Override
        public void initialize(final ValidSearchEndEntitiesSearchRestRequestV2 validSearchEndEntitiesSearchRestRequest) {
        }

        @Override
        public boolean isValid(final SearchEndEntitiesRestRequestV2 searchEndEntitiesRestRequest, final ConstraintValidatorContext constraintValidatorContext) {
            if (searchEndEntitiesRestRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, 
                        "{ValidSearchEndEntitiesSearchRestRequest.invalid.default}");
                return false;
            }
            if (searchEndEntitiesRestRequest.getMaxNumberOfResults() == null || searchEndEntitiesRestRequest.getMaxNumberOfResults() < 0) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, 
                        "{ValidSearchEndEntitiesSearchRestRequest.invalid.invalidmaxnoresult}");
                return false;
            }
            if (searchEndEntitiesRestRequest.getCurrentPage() < 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, 
                        "{ValidSearchEndEntitiesSearchRestRequest.invalid.invalidcurrentpage}");
                return false;
            }
            if ((searchEndEntitiesRestRequest.getCriteria() == null || searchEndEntitiesRestRequest.getCriteria().isEmpty())
                    && searchEndEntitiesRestRequest.getSortOperation() == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, 
                        "{ValidSearchEndEntitiesSearchRestRequest.invalid.nooperation}");
                return false;
            }
            return true;
        }
        
    }
}
