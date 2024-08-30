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

import org.ejbca.ui.web.rest.api.io.request.SetEndEntityStatusRestRequest;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Set;

import static org.junit.Assert.assertEquals;

public class ValidEndEntityStatusRestRequestUnitTest {

    private static final Validator validator = Validation.byDefaultProvider().configure().
        messageInterpolator(new ParameterMessageInterpolator()).buildValidatorFactory().getValidator();
        
    @Test
    public void errorToken() {
        // given
        final String expectedMessage = "Invalid SetEndEntityStatusRestRequest content, token cannot be null or empty.";
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
        final String expectedMessage = "Invalid SetEndEntityStatusRestRequest content, unrecognized token.";
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
        final String expectedMessage = "Invalid SetEndEntityStatusRestRequest content, status cannot be null or empty.";
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
        final String expectedMessage = "Invalid SetEndEntityStatusRestRequest content, unrecognized status.";
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
