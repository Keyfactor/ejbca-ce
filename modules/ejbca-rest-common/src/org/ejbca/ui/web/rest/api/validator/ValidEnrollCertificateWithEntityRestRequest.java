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
import org.apache.commons.lang.StringUtils;
import org.ejbca.ui.web.rest.api.io.request.EnrollCertificateWithEntityRestRequest;
import org.ejbca.ui.web.rest.api.io.request.RequestType;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidEnrollCertificateWithEntityRestRequest.Validator.class})
@Documented
public @interface ValidEnrollCertificateWithEntityRestRequest {

    String message() default "{ValidAddEndEntityRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidEnrollCertificateWithEntityRestRequest, EnrollCertificateWithEntityRestRequest> {
        @Override
        public boolean isValid(EnrollCertificateWithEntityRestRequest enrollCertificateWithEntityRestRequest, ConstraintValidatorContext constraintValidatorContext) {
            if (enrollCertificateWithEntityRestRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEnrollCertificateWithEntityRestRequest.invalid.null}");
                return false;
            }

            if (enrollCertificateWithEntityRestRequest.getEndEntity() == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEnrollCertificateWithEntityRestRequest.invalid.endentity.null}");
                return false;
            }

            if (StringUtils.isEmpty(enrollCertificateWithEntityRestRequest.getCertificateRequest())) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEnrollCertificateWithEntityRestRequest.invalid.request.null}");
                return false;
            }

            final String requestTypeValue = enrollCertificateWithEntityRestRequest.getCertificateRequestType();
            if (StringUtils.isEmpty(requestTypeValue)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEnrollCertificateWithEntityRestRequest.invalid.requestType.nullOrEmpty}");
                return false;
            }
            final RequestType tokenType = RequestType.resolveRequestTypeStatusByName(requestTypeValue);
            if (tokenType == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEnrollCertificateWithEntityRestRequest.invalid.requestType.unknown}");
                return false;
            }

            return true;
        }

        @Override
        public void initialize(ValidEnrollCertificateWithEntityRestRequest enrollCertificateWithEntityRestRequest) {
        }
    }
}
