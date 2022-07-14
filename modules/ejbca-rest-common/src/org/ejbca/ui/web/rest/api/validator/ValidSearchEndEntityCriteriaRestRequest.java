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
import org.ejbca.ui.web.rest.api.io.request.SearchEndEntityCriteriaRestRequest;

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
import static org.ejbca.ui.web.rest.api.io.request.SearchEndEntityCriteriaRestRequest.CriteriaOperation.EQUAL;

/**
 * Validation annotation for input parameter with built-in validator. An input SearchEndEntityCriteriaRestRequest is validated for:
 * <ul>
 *     <li>Not null.</li>
 * </ul>
 *
 * SearchEndEntityCriteriaRestRequest's property attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>One of SearchEndEntityCriteriaRestRequest.CriteriaProperty.</li>
 * </ul>
 *
 * SearchEndEntityCriteriaRestRequest's value attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>In case of END_ENTITY_PROFILE, CERTIFICATE_PROFILE, CA:
 *         <ul>
 *             <li>The value has to be exact string.</li>
 *         </ul>
 *     </li>
 *     <li>In case of STATUS:
 *         <ul>
 *             <li>The value has to be one of SearchEndEntityCriteriaRestRequest.EndEntityStatus.</li>
 *         </ul>
 *     </li>
 * </ul>
 *
 * SearchEndEntityCriteriaRestRequest's operation attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>One of SearchEndEntityCriteriaRestRequest.CriteriaOperation.</li>
 * </ul>
 *
 * The property and operation attributes should be in accordance:
 * <ul>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.QUERY supports operations SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL and SearchCertificateCriteriaRestRequest.CriteriaOperation.LIKE;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.END_ENTITY_PROFILE supports operation SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.CERTIFICATE_PROFILE supports operation SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.CA supports operation SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.STATUS supports operation SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL;</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSearchEndEntityCriteriaRestRequest.Validator.class})
@Documented
public @interface ValidSearchEndEntityCriteriaRestRequest {

    String message() default "{ValidSearchEndEntityCriteriaRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidSearchEndEntityCriteriaRestRequest, SearchEndEntityCriteriaRestRequest> {

        @Override
        public void initialize(final ValidSearchEndEntityCriteriaRestRequest validSearchEndEntityCriteriaRestRequest) {
        }

        @Override
        public boolean isValid(final SearchEndEntityCriteriaRestRequest searchEndEntityCriteriaRestRequest, final ConstraintValidatorContext constraintValidatorContext) {
            if (searchEndEntityCriteriaRestRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequest.invalid.null}");
                return false;
            }
            final String property = searchEndEntityCriteriaRestRequest.getProperty();
            if (StringUtils.isEmpty(property)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequest.invalid.property.nullOrEmpty}");
                return false;
            }
            final String value = searchEndEntityCriteriaRestRequest.getValue();
            if (StringUtils.isEmpty(value)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequest.invalid.value.nullOrEmpty}");
                return false;
            }
            final String operation = searchEndEntityCriteriaRestRequest.getOperation();
            if (StringUtils.isEmpty(operation)) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequest.invalid.operation.nullOrEmpty}");
                return false;
            }
            //
            final SearchEndEntityCriteriaRestRequest.CriteriaProperty criteriaProperty = SearchEndEntityCriteriaRestRequest.CriteriaProperty.resolveCriteriaProperty(property);
            if (criteriaProperty == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequest.invalid.property.unknown}");
                return false;
            }
            final SearchEndEntityCriteriaRestRequest.CriteriaOperation criteriaOperation = SearchEndEntityCriteriaRestRequest.CriteriaOperation.resolveCriteriaOperation(operation);
            if (criteriaOperation == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequest.invalid.operation.unknown}");
                return false;
            }
            // Check the correlation between Property - Value - Operator
            switch (criteriaProperty) {
                // Value: Any String
                // Operation: EQUALS
                case END_ENTITY_PROFILE:
                case CERTIFICATE_PROFILE:
                case CA: {
                    if (criteriaOperation != EQUAL) {
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequest.invalid.operation.notEqual}");
                        return false;
                    }
                    break;
                }
                // Value: Proper end entity status
                // Operation: EQUALS
                case STATUS: {
                    if (criteriaOperation != EQUAL) {
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequest.invalid.operation.notEqual}");
                        return false;
                    }
                    final SearchEndEntityCriteriaRestRequest.EndEntityStatus endEntityStatus = SearchEndEntityCriteriaRestRequest.EndEntityStatus.resolveEndEntityStatusByName(value);
                    if(endEntityStatus == null) {
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchEndEntityCriteriaRestRequest.invalid.value.unknownStatus}");
                        return false;
                    }
                    break;
                }
                // Value: Proper token type
                // Operation: EQUALS
                default:
                    // Do nothing
            }

            return true;
        }
    }
}
