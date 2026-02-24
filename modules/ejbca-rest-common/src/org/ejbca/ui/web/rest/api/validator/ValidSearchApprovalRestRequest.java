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
import org.ejbca.ui.web.rest.api.io.request.SearchApprovalRestRequest;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Validator annotation for SearchApprovalRestRequest.
 * Validates that the request parameters are correctly set.
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = {ValidSearchApprovalRestRequest.Validator.class})
@Documented
public @interface ValidSearchApprovalRestRequest {

    String message() default "Invalid search approval request parameters";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidSearchApprovalRestRequest, SearchApprovalRestRequest> {
        @Override
        public void initialize(final ValidSearchApprovalRestRequest constraintAnnotation) {
        }

        @Override
        public boolean isValid(final SearchApprovalRestRequest request,
                               final ConstraintValidatorContext context) {
            if (request == null) {
                return false;
            }

            if (!isValidDates(request) || !isValidEmail(request.getEmail())) {
                return false;
            }

            // At least one search criteria should be set
            return request.isSearchingWaitingForMe() ||
                    request.isSearchingPending() ||
                    request.isSearchingHistorical() ||
                    request.isSearchingExpired() ||
                    request.getStartDate() != null ||
                    request.getEndDate() != null ||
                    request.getExpiresBefore() != null ||
                    request.getSubjectDn() != null ||
                    request.getEmail() != null;
        }

        private boolean isValidDates(final SearchApprovalRestRequest request) {
            if (request.getStartDate() != null && request.getEndDate() != null) {
                return request.getStartDate().before(request.getEndDate());
            }
            return true;
        }

        private boolean isValidEmail(final String email) {
            if (email == null) {
                return true;
            }
            return email.matches("^[A-Za-z0-9+_.-]+@(.+)$");
        }
    }
}
