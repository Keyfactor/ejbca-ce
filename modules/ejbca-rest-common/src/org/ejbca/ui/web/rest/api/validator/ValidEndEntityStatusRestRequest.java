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
import org.ejbca.ui.web.rest.api.io.request.SetEndEntityStatusRestRequest;

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
 * Validation annotation for input parameter with built-in validator. An input SetEndEntityStatusRestRequest is validated for:
 * <ul>
 *     <li>Not null.</li>
 * </ul>
 *
 * SetEndEntityStatusRestRequest token attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>The value has to be one of EditEndEntityRestRequest.TokenTypes.</li>
 * </ul>
 * 
 * SetEndEntityStatusRestRequest status attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>The value has to be one of SetEndEntityStatusRestRequest.EndEntityStatuses.</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidEndEntityStatusRestRequest.Validator.class})
@Documented
public @interface ValidEndEntityStatusRestRequest {

    String message() default "{ValidEditEndEntityRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidEndEntityStatusRestRequest, SetEndEntityStatusRestRequest> {

        @Override
        public void initialize(final ValidEndEntityStatusRestRequest validEditEndEntityRestRequest) {
        }

        @Override
        public boolean isValid(final SetEndEntityStatusRestRequest editEndEntityRestRequest, final ConstraintValidatorContext constraintValidatorContext) {
            if (editEndEntityRestRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.null}");
                return false;
            }
            final String tokenValue = editEndEntityRestRequest.getToken();
            if (StringUtils.isEmpty(tokenValue)) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.token.nullOrEmpty}");
                return false;
            }
            final SetEndEntityStatusRestRequest.TokenType tokenType = SetEndEntityStatusRestRequest.TokenType.resolveEndEntityTokenByName(tokenValue);
            if (tokenType == null) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.token.unknown}");
                return false;
            }
            final String statusValue = editEndEntityRestRequest.getStatus();
            if (StringUtils.isEmpty(statusValue)) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.status.nullOrEmpty}");
                return false;
            }
            final SetEndEntityStatusRestRequest.EndEntityStatus endEntityStatus = SetEndEntityStatusRestRequest.EndEntityStatus.resolveEndEntityStatusByName(statusValue);
            if (endEntityStatus == null) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.status.unknown}");
                return false;
            }

            return true;
        }
    }
}
