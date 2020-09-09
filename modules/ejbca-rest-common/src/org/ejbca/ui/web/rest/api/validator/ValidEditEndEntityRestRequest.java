package org.ejbca.ui.web.rest.api.validator;

import org.ejbca.ui.web.rest.api.io.request.EditEndEntityRestRequest;

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
 * Validation annotation for input parameter with built-in validator. An input EditEndEntityRestRequest is validated for:
 * <ul>
 *     <li>Not null.</li>
 * </ul>
 *
 * EditEndEntityRestRequest's token attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>The value has to be one of EditEndEntityRestRequest.TokenTypes.</li>
 * </ul>
 * 
 * EditEndEntityRestRequest's status attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>The value has to be one of EditEndEntityRestRequest.EndEntityStatuses.</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidEditEndEntityRestRequest.Validator.class})
@Documented
public @interface ValidEditEndEntityRestRequest {

    String message() default "{ValidEditEndEntityRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidEditEndEntityRestRequest, EditEndEntityRestRequest> {

        @Override
        public void initialize(final ValidEditEndEntityRestRequest validEditEndEntityRestRequest) {
        }

        @Override
        public boolean isValid(final EditEndEntityRestRequest editEndEntityRestRequest, final ConstraintValidatorContext constraintValidatorContext) {
            if (editEndEntityRestRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.null}");
                return false;
            }
            final String tokenValue = editEndEntityRestRequest.getToken();
            if (tokenValue == null || tokenValue.isEmpty()) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.token.nullOrEmpty}");
                return false;
            }
            final EditEndEntityRestRequest.TokenType tokenType = EditEndEntityRestRequest.TokenType.resolveEndEntityTokenByName(tokenValue);
            if (tokenType == null) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.token.unknown}");
                return false;
            }
            final String statusValue = editEndEntityRestRequest.getStatus();
            if (statusValue == null || statusValue.isEmpty()) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.status.nullOrEmpty}");
                return false;
            }
            final EditEndEntityRestRequest.EndEntityStatus endEntityStatus = EditEndEntityRestRequest.EndEntityStatus.resolveEndEntityStatusByName(statusValue);
            if (endEntityStatus == null) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.status.unknown}");
                return false;
            }

            return true;
        }
    }
}
