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
import org.apache.commons.lang.StringUtils;
import org.ejbca.ui.web.rest.api.io.request.KeyImportRestRequestV2;
import org.ejbca.ui.web.rest.api.io.request.KeystoreRestRequestComponent;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.List;
import java.util.regex.Pattern;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidKeyImportRestRequest.Validator.class})
@Documented
public @interface ValidKeyImportRestRequest {
    String message() default "{ValidKeyImportRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidKeyImportRestRequest, KeyImportRestRequestV2> {

        @Override
        public void initialize(final ValidKeyImportRestRequest constraintAnnotation) {
        }

        @Override
        public boolean isValid(KeyImportRestRequestV2 request, ConstraintValidatorContext constraintValidatorContext) {
            if (request == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidKeyImportRestRequest.invalid.null}");
                return false;
            }

            final String certificateProfileName = request.getCertificateProfileName();
            if (StringUtils.isBlank(certificateProfileName)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidKeyImportRestRequest.invalid.certificateProfileName.nullOrEmpty}");
                return false;
            }

            final String endEntityProfileName = request.getEndEntityProfileName();
            if (StringUtils.isBlank(endEntityProfileName)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidKeyImportRestRequest.invalid.endEntityProfileName.nullOrEmpty}");
                return false;
            }

            final List<KeystoreRestRequestComponent> keystores = request.getKeystores();
            if (keystores == null || keystores.isEmpty()) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidKeyImportRestRequest.invalid.keystores.nullOrEmpty}");
                return false;
            }

            for (KeystoreRestRequestComponent keystore : keystores) {
                if (StringUtils.isBlank(keystore.getUsername())) {
                    ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidKeyImportRestRequest.invalid.keystore.username.nullOrEmpty}");
                    return false;
                }

                if (StringUtils.isBlank(keystore.getPassword())) {
                    ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidKeyImportRestRequest.invalid.keystore.password.nullOrEmpty}");
                    return false;
                }

                if (StringUtils.isBlank(keystore.getKeystore())) {
                    ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidKeyImportRestRequest.invalid.keystore.keystore.nullOrEmpty}");
                    return false;
                }

                final Pattern pattern = Pattern.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");
                if (!pattern.matcher(keystore.getKeystore()).matches()) {
                    ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidKeyImportRestRequest.invalid.keystore.keystore.invalid}");
                    return false;
                }
            }

            return true;
        }
    }

}
