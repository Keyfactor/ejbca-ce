package org.ejbca.ui.web.rest.api.resource.validator;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.rest.api.io.request.SetEndEntityStatusRestRequest;
import org.junit.Test;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.util.Set;

import static org.junit.Assert.assertEquals;

public class ValidEndEntityStatusRestRequestTest {

    private static Logger log = Logger.getLogger(ValidEndEntityStatusRestRequestTest.class);
    private static final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    public void errorToken() {
        // given
        final String expectedMessage = "Invalid edit end entity request, token cannot be null or empty.";
        final SetEndEntityStatusRestRequest testClass = new SetEndEntityStatusRestRequest();
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorTokenValue() {
        // given
        final String expectedMessage = "Invalid edit end entity request, unrecognized token.";
        final SetEndEntityStatusRestRequest testClass = new SetEndEntityStatusRestRequest();
        testClass.setToken("Token");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorStatus() {
        // given
        final String expectedMessage = "Invalid edit end entity request, status cannot be null or empty.";
        final SetEndEntityStatusRestRequest testClass = new SetEndEntityStatusRestRequest();
        testClass.setToken("P12");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorStatusValue() {
        // given
        final String expectedMessage = "Invalid edit end entity request, unrecognized status.";
        final SetEndEntityStatusRestRequest testClass = new SetEndEntityStatusRestRequest();
        testClass.setToken("P12");
        testClass.setStatus("Status");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void okRequest() {
        // given
        final SetEndEntityStatusRestRequest testClass = new SetEndEntityStatusRestRequest();
        testClass.setToken("P12");
        testClass.setStatus("NEW");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(0, constraintViolations.size());
    }


}
