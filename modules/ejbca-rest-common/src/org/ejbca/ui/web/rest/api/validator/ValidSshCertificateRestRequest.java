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

import org.apache.commons.lang.StringUtils;
import org.ejbca.ui.web.rest.api.io.request.SshCertificateRequestRestRequest;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSshCertificateRestRequest.Validator.class})
@Documented
public @interface ValidSshCertificateRestRequest {

    String message() default "{ValidSshCertificateRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
    class Validator implements ConstraintValidator<ValidSshCertificateRestRequest, SshCertificateRequestRestRequest> {
        @Override
        public void initialize(ValidSshCertificateRestRequest validSshCertificateRestRequest) {

        }

        @Override
        public boolean isValid(SshCertificateRequestRestRequest sshCertificateRequestRestRequest, ConstraintValidatorContext constraintValidatorContext) {
            if (StringUtils.isBlank(sshCertificateRequestRestRequest.getPublicKey())) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSshCertificateRestRequest.invalid.publicKey.blank}");
                return false;
            }
            if (StringUtils.isBlank(sshCertificateRequestRestRequest.getKeyId()) ) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSshCertificateRestRequest.invalid.keyId.blank}");
                return false;
            }
            if (StringUtils.isBlank(sshCertificateRequestRestRequest.getEndEntityProfile())) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSshCertificateRestRequest.invalid.endEntityProfile.blank}");
                return false;
            }
            if (StringUtils.isBlank(sshCertificateRequestRestRequest.getUsername())) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSshCertificateRestRequest.invalid.username.blank}");
                return false;
            }
            if (StringUtils.isBlank(sshCertificateRequestRestRequest.getPassword())) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSshCertificateRestRequest.invalid.password.blank}");
                return false;
            }
            return true;
        }
    }
}
