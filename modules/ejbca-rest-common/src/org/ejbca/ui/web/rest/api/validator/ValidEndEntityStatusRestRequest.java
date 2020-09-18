package org.ejbca.ui.web.rest.api.validator;

import org.ejbca.ui.web.rest.api.io.request.SetEndEntityStatusRestRequest;

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
 * Validation annotation for input parameter with built-in validator. An input SetEndEntityStatusRestRequest is validated for:
 * <ul>
 *     <li>Not null.</li>
 * </ul>
 *
 * SetEndEntityStatusRestRequest token attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>The value has to be one of EditEndEntityRestRequest.TokenTypes.</li>
 * </ul>
 * 
 * SetEndEntityStatusRestRequest status attribute is validated for:
 * <ul>
 *     <li>Not null;</li>
 *     <li>Not empty;</li>
 *     <li>The value has to be one of SetEndEntityStatusRestRequest.EndEntityStatuses.</li>
 * </ul>
 */
@Target({TYPE, FIELD, PARAMETER})
@Retention(RUNTIME)
@Constraint(validatedBy = {ValidEndEntityStatusRestRequest.Validator.class})
@Documented
public @interface ValidEndEntityStatusRestRequest {

    String message() default "{ValidEditEndEntityRestRequest.invalid.default}";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};

    class Validator implements ConstraintValidator<ValidEndEntityStatusRestRequest, SetEndEntityStatusRestRequest> {

        @Override
        public void initialize(final ValidEndEntityStatusRestRequest validEditEndEntityRestRequest) {
        }

        @Override
        public boolean isValid(final SetEndEntityStatusRestRequest editEndEntityRestRequest, final ConstraintValidatorContext constraintValidatorContext) {
            if (editEndEntityRestRequest == null) {
                ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.null}");
                return false;
            }
            final String tokenValue = editEndEntityRestRequest.getToken();
            if (tokenValue == null || tokenValue.isEmpty()) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.token.nullOrEmpty}");
                return false;
            }
            final SetEndEntityStatusRestRequest.TokenType tokenType = SetEndEntityStatusRestRequest.TokenType.resolveEndEntityTokenByName(tokenValue);
            if (tokenType == null) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.token.unknown}");
                return false;
            }
            final String statusValue = editEndEntityRestRequest.getStatus();
            if (statusValue == null || statusValue.isEmpty()) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.status.nullOrEmpty}");
                return false;
            }
            final SetEndEntityStatusRestRequest.EndEntityStatus endEntityStatus = SetEndEntityStatusRestRequest.EndEntityStatus.resolveEndEntityStatusByName(statusValue);
            if (endEntityStatus == null) {
            	ValidationHelper.addConstraintViolation(constraintValidatorContext, "{ValidEditEndEntityRestRequest.invalid.status.unknown}");
                return false;
            }

            return true;
        }
    }
}
