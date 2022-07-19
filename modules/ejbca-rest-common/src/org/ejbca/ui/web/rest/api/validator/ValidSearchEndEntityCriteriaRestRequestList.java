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

import org.ejbca.ui.web.rest.api.io.request.SearchEndEntityCriteriaRestRequest;

import static org.ejbca.ui.web.rest.api.io.request.SearchEndEntityCriteriaRestRequest.EndEntityStatus;
import static org.ejbca.ui.web.rest.api.io.request.SearchEndEntityCriteriaRestRequest.CriteriaProperty;

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
 * Validation annotation for input parameter with built-in validator. An input List of SearchEndEntityCriteriaRestRequest is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty.</li>
 *     <li>
 *         The list should contain proper count of criteria per property:
 *         <ul>
 *             <li>QUERY: 0 - 1;</li>
 *             <li>END_ENTITY_PROFILE: 0 - *;</li>
 *             <li>CERTIFICATE_PROFILE: 0 - *;</li>
 *             <li>CA: 0 - *;</li>
 *             <li>STATUS: 0 - 9;</li>
 *         </ul>
 *     </li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSearchEndEntityCriteriaRestRequestList.Validator.class})
@Documented
public @interface ValidSearchEndEntityCriteriaRestRequestList {

    String message() default "{ValidSearchEndEntityCriteriaRestRequestList.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidSearchEndEntityCriteriaRestRequestList, List<SearchEndEntityCriteriaRestRequest>> {

        @Override
        public void initialize(final ValidSearchEndEntityCriteriaRestRequestList validSearchEndEntityCriteriaRestRequestList) {
        }

        @Override
        public boolean isValid(final List<SearchEndEntityCriteriaRestRequest> searchEndEntityCriteriaRestRequests, final ConstraintValidatorContext constraintValidatorContext) {
            if(searchEndEntityCriteriaRestRequests == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequestList.invalid.null}");
                return false;
            }
            if (searchEndEntityCriteriaRestRequests.isEmpty()) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequestList.invalid.empty}");
                return false;
            }
            // Count criteria properties
            int queryCount = 0;
            int statusCount = 0;
            for(SearchEndEntityCriteriaRestRequest searchEndEntityCriteriaRestRequest : searchEndEntityCriteriaRestRequests) {
                final CriteriaProperty criteriaProperty = CriteriaProperty.resolveCriteriaProperty(searchEndEntityCriteriaRestRequest.getProperty());
                // Ignore null-s as their validation is completed on lower levels
                if(criteriaProperty != null) {
                    //final CriteriaOperation criteriaOperation = CriteriaOperation.resolveCriteriaOperation(searchEndEntityCriteriaRestRequest.getOperation());
                    switch (criteriaProperty) {
                    	case QUERY:
                    		queryCount++;
                    		break;
                        case STATUS:
                            statusCount++;
                            break;
                        default:
                            // do nothing
                    }
                }
            }
            if(queryCount > 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequestList.invalid.multipleQueries}");
                return false;
            }
            if(statusCount > EndEntityStatus.values().length) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequestList.invalid.statusRepetition}");
                return false;
            }
            return true;
        }
    }
}
