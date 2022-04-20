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
import org.ejbca.ui.web.rest.api.io.request.AddEndEntityRestRequest;

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

/**
 * Validation annotation for input parameter with built-in validator. An input AddEndEntityRestRequest is validated for:
 * <ul>
 *     <li>Not null.</li>
 * </ul>
 *
 * AddEndEntityRestRequest's username attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 * 
 * AddEndEntityRestRequest's subjectDn attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 * 
 * AddEndEntityRestRequest's caName attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 * 
 * AddEndEntityRestRequest's certificateProfileName attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 * 
 * AddEndEntityRestRequest's endEntityProfileName attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 *
 * AddEndEntityRestRequest's token attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>The value has to be one of AddEndEntityRestRequest.TokenTypes.</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidAddEndEntityRestRequest.Validator.class})
@Documented
public @interface ValidAddEndEntityRestRequest {

    String message() default "{ValidAddEndEntityRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidAddEndEntityRestRequest, AddEndEntityRestRequest> {

        @Override
        public void initialize(final ValidAddEndEntityRestRequest validAddEndEntityRestRequest) {
        }

        @Override
        public boolean isValid(final AddEndEntityRestRequest addEndEntityRestRequest, final ConstraintValidatorContext constraintValidatorContext) {
            if (addEndEntityRestRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidAddEndEntityRestRequest.invalid.null}");
                return false;
            }
            final String username = addEndEntityRestRequest.getUsername();
            if (StringUtils.isEmpty(username)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidAddEndEntityRestRequest.invalid.username.nullOrEmpty}");
                return false;
            }
            final String subjectDn = addEndEntityRestRequest.getSubjectDn();
            if (StringUtils.isEmpty(subjectDn)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidAddEndEntityRestRequest.invalid.subjectDn.nullOrEmpty}");
                return false;
            }
            final String caName = addEndEntityRestRequest.getCaName();
            if (StringUtils.isEmpty(caName)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidAddEndEntityRestRequest.invalid.caName.nullOrEmpty}");
                return false;
            }
            final String certificateProfileName = addEndEntityRestRequest.getCertificateProfileName();
            if (StringUtils.isEmpty(certificateProfileName)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidAddEndEntityRestRequest.invalid.certificateProfileName.nullOrEmpty}");
                return false;
            }
            final String endEntityProfileName = addEndEntityRestRequest.getEndEntityProfileName();
            if (StringUtils.isEmpty(endEntityProfileName)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidAddEndEntityRestRequest.invalid.endEntityProfileName.nullOrEmpty}");
                return false;
            }
            final String tokenValue = addEndEntityRestRequest.getToken();
            if (StringUtils.isEmpty(tokenValue)) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidAddEndEntityRestRequest.invalid.token.nullOrEmpty}");
                return false;
            }
            final AddEndEntityRestRequest.TokenType tokenType = AddEndEntityRestRequest.TokenType.resolveEndEntityTokenByName(tokenValue);
            if (tokenType == null) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidAddEndEntityRestRequest.invalid.token.unknown}");
                return false;
            }

            return true;
        }
    }
}
