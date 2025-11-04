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

import org.ejbca.ui.web.rest.api.io.request.EndEntityRevocationRestRequest;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Set;

import static org.junit.Assert.assertEquals;

public class ValidEndEntityRevocationRestRequestUnitTest {
    private static final Validator validator = Validation.byDefaultProvider().configure()
                                                         .messageInterpolator(new ParameterMessageInterpolator())
                                                         .buildValidatorFactory().getValidator();

    @Test
    public void errorRevocationReason() {
        // Given
        final String expectedMessage = "Invalid EndEntityRevocationRestRequest property, unrecognized reason, must be one of RFC5280 section 5.3.1..";
        final EndEntityRevocationRestRequest testClass = new EndEntityRevocationRestRequest();
        testClass.setReasonCode(-100);  // to create a reason that is not available in RevocationReasons

        // When
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void okRequest() {
        // Given
        final EndEntityRevocationRestRequest testClass = new EndEntityRevocationRestRequest();
        testClass.setReasonCode(1);

        // When
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(0, constraintViolations.size());
    }
}
