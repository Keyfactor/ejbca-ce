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

import org.apache.commons.lang3.StringUtils;
import org.ejbca.ui.web.rest.api.io.request.SearchEndEntitiesSortRestRequest;

/**
 * Validation annotation for input parameter with built-in validator. An input SearchEndEntitiesSortRestRequest is validated for:
 *
 * SearchEndEntitiesSortRestRequest property attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not blank;</li>
 *     <li>One of SearchEndEntitiesSortRestRequest.CriteriaProperty.</li>
 * </ul>
 *
 * SearchEndEntitiesSortRestRequest operation attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not blank;</li>
 *     <li>One of SearchEndEntitiesSortRestRequest.SortProperty.</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSearchEndEntitiesSortRestRequest.Validator.class})
@Documented
public @interface ValidSearchEndEntitiesSortRestRequest {

    String message() default "{ValidSearchCertificateSortRestRequest.invalid.sort.default}"; // same error messages

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    final class Validator implements ConstraintValidator<ValidSearchEndEntitiesSortRestRequest, SearchEndEntitiesSortRestRequest> {

        @Override
        public void initialize(final ValidSearchEndEntitiesSortRestRequest request) {
        }

        @Override
        public boolean isValid(final SearchEndEntitiesSortRestRequest restRequest, final ConstraintValidatorContext context) {
            if (restRequest != null) {
                final String property = restRequest.getProperty();
                final String operation = restRequest.getOperation();
                if (StringUtils.isNotBlank(property)) {
                    final SearchEndEntitiesSortRestRequest.SortProperty criteriaProperty = SearchEndEntitiesSortRestRequest.SortProperty.resolveCriteriaProperty(property.trim());
                    if (criteriaProperty == null) {
                        ValidationHelper.addConstraintViolation(context, "{ValidSearchCertificateSortRestRequest.invalid.property.unknown}");
                        return false;
                    }
                }
                if (StringUtils.isNotBlank(operation)) {
                    final SearchEndEntitiesSortRestRequest.SortOperation criteriaOperation = SearchEndEntitiesSortRestRequest.SortOperation.resolveCriteriaOperation(operation.trim());
                    if (criteriaOperation == null) {
                        ValidationHelper.addConstraintViolation(context, "{ValidSearchCertificateSortRestRequest.invalid.operation.unknown}");
                        return false;
                    }
                }
            }
            return true;
        }
    }
}
