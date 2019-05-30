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

import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CertificateStatus;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaProperty;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaOperation;

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
 *     <li>
 *         The list should contain proper count of criteria per property:
 *         <ul>
 *             <li>QUERY: 0 - 1;</li>
 *             <li>END_ENTITY_PROFILE: 0 - *;</li>
 *             <li>CERTIFICATE_PROFILE: 0 - *;</li>
 *             <li>CA: 0 - *;</li>
 *             <li>STATUS: 0 - 12;</li>
 *             <li>ISSUED_DATE: 0 - 2;</li>
 *             <li>EXPIRE_DATE: 0 - 2;</li>
 *             <li>REVOCATION_DATE: 0 - 2.</li>
 *         </ul>
 *     </li>
 * </ul>
 *
 * @version $Id: ValidSearchCertificateCriteriaRestRequestList.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
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
            // Count criteria properties
            int queryCount = 0;
            int statusCount = 0;
            int issuedDateBeforeCount = 0;
            int issuedDateAfterCount = 0;
            int revocationDateBeforeCount = 0;
            int revocationDateAfterCount = 0;
            int expireDateBeforeCount = 0;
            int expireDateAfterCount = 0;
            for(SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest : searchCertificateCriteriaRestRequests) {
                final CriteriaProperty criteriaProperty = CriteriaProperty.resolveCriteriaProperty(searchCertificateCriteriaRestRequest.getProperty());
                // Ignore null-s as their validation is completed on lower levels
                if(criteriaProperty != null) {
                    final CriteriaOperation criteriaOperation = CriteriaOperation.resolveCriteriaOperation(searchCertificateCriteriaRestRequest.getOperation());
                    switch (criteriaProperty) {
                        case QUERY:
                            queryCount++;
                            break;
                        case STATUS:
                            statusCount++;
                            break;
                        case ISSUED_DATE:
                            if(criteriaOperation == CriteriaOperation.BEFORE) issuedDateBeforeCount++;
                            if(criteriaOperation == CriteriaOperation.AFTER) issuedDateAfterCount++;
                            break;
                        case REVOCATION_DATE:
                            if(criteriaOperation == CriteriaOperation.BEFORE) revocationDateBeforeCount++;
                            if(criteriaOperation == CriteriaOperation.AFTER) revocationDateAfterCount++;
                            break;
                        case EXPIRE_DATE:
                            if(criteriaOperation == CriteriaOperation.BEFORE) expireDateBeforeCount++;
                            if(criteriaOperation == CriteriaOperation.AFTER) expireDateAfterCount++;
                            break;
                        default:
                            // do nothing
                    }
                }
            }
            if(queryCount > 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleQueries}");
                return false;
            }
            if(statusCount > CertificateStatus.values().length) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.statusRepetition}");
                return false;
            }
            if(issuedDateBeforeCount > 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleIssuedDateBefore}");
                return false;
            }
            if(issuedDateAfterCount > 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleIssuedDateAfter}");
                return false;
            }
            if(revocationDateBeforeCount > 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleRevocationDateBefore}");
                return false;
            }
            if(revocationDateAfterCount > 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleRevocationDateAfter}");
                return false;
            }
            if(expireDateBeforeCount > 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleExpireDateBefore}");
                return false;
            }
            if(expireDateAfterCount > 1) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequestList.invalid.multipleExpireDateAfter}");
                return false;
            }
            return true;
        }
    }
}
