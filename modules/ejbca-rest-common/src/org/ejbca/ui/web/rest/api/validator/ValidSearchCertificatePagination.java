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

import org.ejbca.ui.web.rest.api.io.request.Pagination;

/**
 * Validation annotation for input parameter with built-in validator.
 * 
 * An input integer is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not less than 1</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSearchCertificatePagination.Validator.class})
@Documented
public @interface ValidSearchCertificatePagination {

    String message() default "{ValidSearchCertificatePagination.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidSearchCertificatePagination, Pagination> {

        @Override
        public void initialize(final ValidSearchCertificatePagination validSearchCertificatePagination) {
        }

        @Override
        public boolean isValid(final Pagination value, final ConstraintValidatorContext constraintValidatorContext) {
            if(value != null && value.getCurrentPage() < 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificatePaginationCurrentPage.invalid.overflow}");
                return false;
            }
            if(value != null && value.getPageSize() < 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificatePaginationPageSize.invalid.overflow}");
                return false;
            }
            return true;
        }
    }

}
