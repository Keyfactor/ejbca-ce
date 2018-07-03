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

import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.List;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * Validation annotation for input parameter with built-in validator. An input List of SearchCertificateCriteriaRestRequest is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty.</li>
 * </ul>
 *
 * @version $Id: ValidSearchCertificateCriteriaRestRequestList.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSearchCertificateCriteriaRestRequestList.Validator.class})
@Documented
public @interface ValidSearchCertificateCriteriaRestRequestList {

    String message() default "{ValidSearchCertificateCriteriaRestRequestList.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidSearchCertificateCriteriaRestRequestList, List<SearchCertificateCriteriaRestRequest>> {

        @Override
        public void initialize(final ValidSearchCertificateCriteriaRestRequestList validSearchCertificateCriteriaRestRequestList) {
        }

        @Override
        public boolean isValid(final List<SearchCertificateCriteriaRestRequest> searchCertificateCriteriaRestRequests, final ConstraintValidatorContext constraintValidatorContext) {
            if(searchCertificateCriteriaRestRequests == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.null}");
                return false;
            }
            if (searchCertificateCriteriaRestRequests.isEmpty()) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.empty}");
                return false;
            }
            return true;
        }
    }
}
