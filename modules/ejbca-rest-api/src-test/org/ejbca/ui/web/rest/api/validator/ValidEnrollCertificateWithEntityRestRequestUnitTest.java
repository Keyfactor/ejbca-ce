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
import org.ejbca.ui.web.rest.api.io.request.EnrollCertificateWithEntityRestRequest;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ValidEnrollCertificateWithEntityRestRequestUnitTest {

    private static final Validator validator = Validation.byDefaultProvider().configure().
            messageInterpolator(new ParameterMessageInterpolator()).buildValidatorFactory().getValidator();

    @Test
    public void errorEmptyType() {
        // given
        final String expectedMessage = "Invalid EnrollCertificateWithEntityRestRequest content, request type cannot be null or empty.";
        final EnrollCertificateWithEntityRestRequest testClass = new EnrollCertificateWithEntityRestRequest();
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }
    @Test
    public void errorRequestType() {
        // given
        final String expectedMessage = "Invalid EnrollCertificateWithEntityRestRequest content, unrecognized request type.";
        final EnrollCertificateWithEntityRestRequest testClass = new EnrollCertificateWithEntityRestRequest();
        testClass.setCertificateRequestType("dummy");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void okRequest() {
        // given
        final EnrollCertificateWithEntityRestRequest testClass = new EnrollCertificateWithEntityRestRequest();
        testClass.setCertificateRequestType("SPKAC");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(0, constraintViolations.size());
    }

}
