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
import java.time.LocalDate;
import java.time.format.DateTimeParseException;

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
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Request body must not be null")
                        .addConstraintViolation();
                return false;
            }

            if (!isValidDates(request)) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("created_on_or_after must be before created_on_or_before")
                        .addPropertyNode("createdOnOrAfter")
                        .addConstraintViolation();
                return false;
            }

            if (!isValidEmail(request.getEmail())) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("Invalid email format")
                        .addPropertyNode("email")
                        .addConstraintViolation();
                return false;
            }

            final String daysExpireIn = request.getDaysRequestsExpireIn();
            if (daysExpireIn != null && !daysExpireIn.isBlank() && !isNonNegativeInt(daysExpireIn)) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("days_requests_expire_in must be a non-negative integer")
                        .addPropertyNode("daysRequestsExpireIn")
                        .addConstraintViolation();
                return false;
            }

            // At least one search criteria should be set
            final boolean hasAnyCriteria = request.isSearchingWaitingForMe() ||
                    request.isSearchingPending() ||
                    request.isSearchingHistorical() ||
                    request.isSearchingExpired() ||
                    request.getCreatedOnOrAfter() != null ||
                    request.getCreatedOnOrBefore() != null ||
                    request.getSubjectDn() != null ||
                    request.getEmail() != null ||
                    request.getDaysRequestsExpireIn() != null;

            if (!hasAnyCriteria) {
                context.disableDefaultConstraintViolation();
                context.buildConstraintViolationWithTemplate("At least one search criteria must be set")
                        .addConstraintViolation();
                return false;
            }

            return true;
        }

        private boolean isNonNegativeInt(final String input) {
            if (input == null) {
                return false;
            }
            try {
                return Integer.parseInt(input.trim()) >= 0;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        private boolean isValidDates(final SearchApprovalRestRequest request) {
            if (request.getCreatedOnOrAfter() != null) {
                try {
                    LocalDate.parse(request.getCreatedOnOrAfter());
                } catch (DateTimeParseException e) {
                    return false;
                }
            }

            if (request.getCreatedOnOrBefore() != null) {
                try {
                    LocalDate.parse(request.getCreatedOnOrBefore());
                } catch (DateTimeParseException e) {
                    return false;
                }
            }

            if (request.getCreatedOnOrAfter() != null && request.getCreatedOnOrBefore() != null) {
                try {
                    final LocalDate after = LocalDate.parse(request.getCreatedOnOrAfter());
                    final LocalDate before = LocalDate.parse(request.getCreatedOnOrBefore());
                    return after.isBefore(before);
                } catch (DateTimeParseException e) {
                    return false;
                }
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
