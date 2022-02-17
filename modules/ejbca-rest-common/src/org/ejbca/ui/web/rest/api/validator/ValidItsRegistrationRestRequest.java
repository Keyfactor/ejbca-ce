/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.validator;

import org.apache.commons.lang.StringUtils;
import org.ejbca.ui.web.rest.api.io.request.ItsRegistrationRequestMessage;

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
 * Validation annotation for input parameter with built-in validator. An input ItsRegistrationRequestMessage is validated for:
 * <ul>
 *     <li>Not null.</li>
 * </ul>
 *
 * ItsRegistrationRequestMessage caninicalId attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 * 
 * ItsRegistrationRequestMessage caninicalPublicKey attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 * 
 * ItsRegistrationRequestMessage certificateProfileName attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 * 
 * ItsRegistrationRequestMessage endEntityProfileName attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 * 
 * ItsRegistrationRequestMessage caName attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidItsRegistrationRestRequest.Validator.class})
@Documented
public @interface ValidItsRegistrationRestRequest {

    String message() default "{ValidEditEndEntityRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidItsRegistrationRestRequest, ItsRegistrationRequestMessage> {

        @Override
        public void initialize(final ValidItsRegistrationRestRequest validItsRegistrationRestRequest) {
        }

        @Override
        public boolean isValid(final ItsRegistrationRequestMessage itsRegistrationRequest, final ConstraintValidatorContext constraintValidatorContext) {
            if (itsRegistrationRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidItsRegistrationRestRequest.invalid.null}");
                return false;
            }
            final String caninicalId = itsRegistrationRequest.getCanonicalId();
            if (StringUtils.isEmpty(caninicalId)) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidItsRegistrationRestRequest.invalid.canonicalId.nullOrEmpty}");
                return false;
            }
            final String canonicalPublicKey = itsRegistrationRequest.getCanonicalPublicKey();
            if (canonicalPublicKey == null) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidItsRegistrationRestRequest.invalid.canonicalPublicKey.nullOrEmpty}}");
                return false;
            }
            final String certificateProfileName = itsRegistrationRequest.getCertificateProfileName();
            if (StringUtils.isEmpty(certificateProfileName)) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidItsRegistrationRestRequest.invalid.certificateProfileName.nullOrEmpty}");
                return false;
            }
            final String endEntityProfileName = itsRegistrationRequest.getEndEntityProfileName();
            if (StringUtils.isEmpty(endEntityProfileName)) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidItsRegistrationRestRequest.invalid.endEntityProfileName.nullOrEmpty}");
                return false;
            }
            final String caName = itsRegistrationRequest.getCaName();
            if (StringUtils.isEmpty(caName)) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidItsRegistrationRestRequest.invalid.caName.nullOrEmpty}");
                return false;
            }

            return true;
        }
    }
}
