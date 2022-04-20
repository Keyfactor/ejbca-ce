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

import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.core.model.util.EjbLocalHelper;

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
 * Validation annotation for input parameter with built-in validator. An input integer is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not negative or equal to zero;</li>
 *     <li>Not more than maximum 400.</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSearchCertificateMaxNumberOfResults.Validator.class})
@Documented
public @interface ValidSearchCertificateMaxNumberOfResults {

    String message() default "{ValidSearchCertificateMaxNumberOfResults.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidSearchCertificateMaxNumberOfResults, Integer> {

        private static final int MINIMUM_INCLUSIVE = 0;
        private static final GlobalConfigurationSessionLocal globalConfigurationSession = new EjbLocalHelper().getGlobalConfigurationSession();
        private static final GlobalCesecoreConfiguration globalCesecoreConfiguration = (GlobalCesecoreConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);

        @Override
        public void initialize(final ValidSearchCertificateMaxNumberOfResults validSearchCertificateMaxNumberOfResults) {
        }

        @Override
        public boolean isValid(final Integer value, final ConstraintValidatorContext constraintValidatorContext) {
            if(value == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateMaxNumberOfResults.invalid.null}");
                return false;
            }
            if(value <= MINIMUM_INCLUSIVE) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateMaxNumberOfResults.invalid.lessThanOrEqualNull}");
                return false;
            }

            final int MAXIMUM_EXCLUSIVE = globalCesecoreConfiguration.getMaximumQueryCount();
            if(value > MAXIMUM_EXCLUSIVE) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateMaxNumberOfResults.invalid.moreThanMaximum}");
                return false;
            }

            return true;
        }
    }

}
