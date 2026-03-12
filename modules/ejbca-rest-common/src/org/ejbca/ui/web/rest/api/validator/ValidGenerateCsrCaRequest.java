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

import org.apache.commons.lang3.StringUtils;
import org.ejbca.ui.web.rest.api.io.request.GenerateCsrCaRequest;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidGenerateCsrCaRequest.Validator.class})
@Documented
public @interface ValidGenerateCsrCaRequest {
    
    String message() default "{ValidGenerateCsrCaRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidGenerateCsrCaRequest, GenerateCsrCaRequest> {

        @Override
        public boolean isValid(GenerateCsrCaRequest generateCsrCaRequest, ConstraintValidatorContext constraintValidatorContext) {
            
            if (StringUtils.isEmpty(generateCsrCaRequest.getKeyPair())) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidGenerateCsrCaRequest.invalid.keypair.nullOrEmpty}");
                return false;
            }
            
            // responseFormat == null -> DER
            if (generateCsrCaRequest.getResponseFormat()!=null &&
                    !(generateCsrCaRequest.getResponseFormat().equals("DER") || 
                            generateCsrCaRequest.getResponseFormat().equals("PEM"))) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidGenerateCsrCaRequest.invalid.responseformat}");
                return false;
            }
            
            if (generateCsrCaRequest.getCertificateChain()!=null && generateCsrCaRequest.getCertificateChain().size() > 10) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidGenerateCsrCaRequest.toolong.certificatechain}");
                return false;
            }
            
            return true;
        }
        
    }

}
