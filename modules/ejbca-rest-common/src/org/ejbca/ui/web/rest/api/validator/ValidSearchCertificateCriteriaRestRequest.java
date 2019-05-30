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
import java.util.regex.Pattern;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaOperation.DATE_OPERATIONS;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL;
import static org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest.CriteriaOperation.STRING_OPERATIONS;

/**
 * Validation annotation for input parameter with built-in validator. An input SearchCertificateCriteriaRestRequest is validated for:
 * <ul>
 *     <li>Not null.</li>
 * </ul>
 *
 * SearchCertificateCriteriaRestRequest's property attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>One of SearchCertificateCriteriaRestRequest.CriteriaProperty.</li>
 * </ul>
 *
 * SearchCertificateCriteriaRestRequest's value attribute is validated for:
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
 *             <li>The value has to be one of SearchCertificateCriteriaRestRequest.CertificateStatus.</li>
 *         </ul>
 *     </li>
 *     <li>In case of ISSUED_DATE, EXPIRE_DATE and REVOCATION_DATE:
 *         <ul>
 *             <li>The value has to contain a date in ISO8601 format, eg. 2019-04-18T07:47:26Z</li>
 *         </ul>
 *     </li>
 * </ul>
 *
 * SearchCertificateCriteriaRestRequest's operation attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>One of SearchCertificateCriteriaRestRequest.CriteriaOperation.</li>
 * </ul>
 *
 * The property and operation attributes should be in accordance:
 * <ul>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.QUERY supports operations SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL and SearchCertificateCriteriaRestRequest.CriteriaOperation.LIKE;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.END_ENTITY_PROFILE supports operation SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.CERTIFICATE_PROFILE supports operation SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.CA supports operation SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.STATUS supports operation SearchCertificateCriteriaRestRequest.CriteriaOperation.EQUAL;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.ISSUED_DATE supports operations SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER and SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.EXPIRE_DATE supports operations SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER and SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE;</li>
 *     <li>SearchCertificateCriteriaRestRequest.CriteriaProperty.REVOCATION_DATE supports operations SearchCertificateCriteriaRestRequest.CriteriaOperation.AFTER and SearchCertificateCriteriaRestRequest.CriteriaOperation.BEFORE;</li>
 * </ul>
 *
 * @version $Id: ValidSearchCertificateCriteriaRestRequest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidSearchCertificateCriteriaRestRequest.Validator.class})
@Documented
public @interface ValidSearchCertificateCriteriaRestRequest {

    String message() default "{ValidSearchCertificateCriteriaRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidSearchCertificateCriteriaRestRequest, SearchCertificateCriteriaRestRequest> {

        private Pattern PATTERN_DATE_ISO8601 = Pattern.compile("^(?:[1-9]\\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29)T(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:Z)$");

        @Override
        public void initialize(final ValidSearchCertificateCriteriaRestRequest validSearchCertificateCriteriaRestRequest) {
        }

        @Override
        public boolean isValid(final SearchCertificateCriteriaRestRequest searchCertificateCriteriaRestRequest, final ConstraintValidatorContext constraintValidatorContext) {
            if (searchCertificateCriteriaRestRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.null}");
                return false;
            }
            final String property = searchCertificateCriteriaRestRequest.getProperty();
            if (property == null || property.isEmpty()) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.property.nullOrEmpty}");
                return false;
            }
            final String value = searchCertificateCriteriaRestRequest.getValue();
            if (value == null || value.isEmpty()) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.value.nullOrEmpty}");
                return false;
            }
            final String operation = searchCertificateCriteriaRestRequest.getOperation();
            if (operation == null || operation.isEmpty()) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.operation.nullOrEmpty}");
                return false;
            }
            //
            final SearchCertificateCriteriaRestRequest.CriteriaProperty criteriaProperty = SearchCertificateCriteriaRestRequest.CriteriaProperty.resolveCriteriaProperty(property);
            if (criteriaProperty == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.property.unknown}");
                return false;
            }
            final SearchCertificateCriteriaRestRequest.CriteriaOperation criteriaOperation = SearchCertificateCriteriaRestRequest.CriteriaOperation.resolveCriteriaOperation(operation);
            if (criteriaOperation == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.operation.unknown}");
                return false;
            }
            // Check the correlation between Property - Value - Operator
            switch (criteriaProperty) {
                // Value: Any String
                // Operation: EQUAL, LIKE
                case QUERY: {
                    if (!STRING_OPERATIONS().contains(criteriaOperation)) {
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.operation.notString}");
                        return false;
                    }
                    break;
                }
                // Value: Any String
                // Operation: EQUAL
                case END_ENTITY_PROFILE:
                case CERTIFICATE_PROFILE:
                case CA: {
                    if (criteriaOperation != EQUAL) {
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.operation.notEqual}");
                        return false;
                    }
                    break;
                }
                // Value: Proper certificate status
                // Operation: EQUAL
                case STATUS: {
                    if (criteriaOperation != EQUAL) {
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.operation.notEqual}");
                        return false;
                    }
                    final SearchCertificateCriteriaRestRequest.CertificateStatus certificateStatus = SearchCertificateCriteriaRestRequest.CertificateStatus.resolveCertificateStatusByName(value);
                    if(certificateStatus == null) {
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.value.unknownStatus}");
                        return false;
                    }
                    break;
                }
                // Value: Date string ISO8601
                // Operation: AFTER or BEFORE
                case ISSUED_DATE:
                case REVOCATION_DATE:
                case EXPIRE_DATE: {
                    if (!PATTERN_DATE_ISO8601.matcher(value).matches()) {
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.value.invalidDate}");
                        return false;
                    }
                    if (!DATE_OPERATIONS().contains(criteriaOperation)) {
                        ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidSearchCertificateCriteriaRestRequest.invalid.operation.notDate}");
                        return false;
                    }
                    break;
                }
                default:
                    // Do nothing
            }

            return true;
        }
    }
}
