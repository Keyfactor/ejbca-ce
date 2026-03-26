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

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Set;
import org.ejbca.ui.web.rest.api.io.request.ApprovalPartitionPropertyRestRequest;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ValidApprovalPartitionPropertyRestRequestUnitTest {

    private static final Validator validator = Validation.byDefaultProvider().configure().
            messageInterpolator(new ParameterMessageInterpolator()).buildValidatorFactory().getValidator();

    @Test
    public void errorEmptyType() {
        // given
        final String expectedMessage = "Invalid ApprovalPartitionPropertyRestRequest content, type can not be null.";
        final ApprovalPartitionPropertyRestRequest testClass = new ApprovalPartitionPropertyRestRequest();
        testClass.setLabel("username");
        testClass.setValue("something wrong");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorWrongType() {
        // given
        final String expectedMessage = "Invalid ApprovalPartitionPropertyRestRequest content, type is unknown.";
        final ApprovalPartitionPropertyRestRequest testClass = new ApprovalPartitionPropertyRestRequest();
        testClass.setLabel("username");
        testClass.setType("somethingWrong");
        testClass.setValue("something wrong");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorWrongInteger() {
        // given
        final String expectedMessage = "Invalid ApprovalPartitionPropertyRestRequest content, value is not a valid integer.";
        final ApprovalPartitionPropertyRestRequest testClass = new ApprovalPartitionPropertyRestRequest();
        testClass.setLabel("username");
        testClass.setType("Integer");
        testClass.setValue("something wrong");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }


    @Test
    public void errorWrongBoolean() {
        // given
        final String expectedMessage = "Invalid ApprovalPartitionPropertyRestRequest content, value is not a boolean. Use 'true' or 'false'.";
        final ApprovalPartitionPropertyRestRequest testClass = new ApprovalPartitionPropertyRestRequest();
        testClass.setLabel("username");
        testClass.setType("Boolean");
        testClass.setValue("something wrong");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
        }
    
        @Test
        public void errorWrongLong() {
            // given
            final String expectedMessage = "Invalid ApprovalPartitionPropertyRestRequest content, value is not a valid Long.";
            final ApprovalPartitionPropertyRestRequest testClass = new ApprovalPartitionPropertyRestRequest();
            testClass.setLabel("username");
            testClass.setType("Long");
            testClass.setValue("invalidLongValue");
            // when
            final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
            // then
            assertEquals(1, constraintViolations.size());
            assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
        }
    
    }
