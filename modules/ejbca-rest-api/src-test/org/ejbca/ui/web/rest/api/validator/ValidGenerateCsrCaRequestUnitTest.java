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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;

import org.ejbca.ui.web.rest.api.io.request.GenerateCsrCaRequest;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;

public class ValidGenerateCsrCaRequestUnitTest {
    private static final Validator validator = Validation.byDefaultProvider().configure()
            .messageInterpolator(new ParameterMessageInterpolator())
            .buildValidatorFactory().getValidator();

    @Test
    public void errorKeyPairNull() {
        // given
        final String expectedMessage = "Invalid GenerateCsrCaRequest keyPair can not be null or empty.";
        final GenerateCsrCaRequest testClass = new GenerateCsrCaRequest();
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }
    
    @Test
    public void errorKeyPairEmpty() {
        // given
        final String expectedMessage = "Invalid GenerateCsrCaRequest keyPair can not be null or empty.";
        final GenerateCsrCaRequest testClass = new GenerateCsrCaRequest();
        testClass.setKeyPair("");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }
    
    @Test
    public void errorResponseFormatInvalid() {
        // given
        final String expectedMessage = "Invalid GenerateCsrCaRequest responseFormat, valid values 'DER' or 'PEM'.";
        final GenerateCsrCaRequest testClass = new GenerateCsrCaRequest();
        testClass.setKeyPair("signKey");
        testClass.setResponseFormat("PKCS12");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }
    
    @Test
    public void errorResponseFormatEmpty() {
        // given
        final String expectedMessage = "Invalid GenerateCsrCaRequest responseFormat, valid values 'DER' or 'PEM'.";
        final GenerateCsrCaRequest testClass = new GenerateCsrCaRequest();
        testClass.setKeyPair("signKey");
        testClass.setResponseFormat("");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }
    
    @Test
    public void validResponseFormatNull() {
        // given
        final GenerateCsrCaRequest testClass = new GenerateCsrCaRequest();
        testClass.setKeyPair("signKey");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertTrue(constraintViolations.isEmpty());
    }
    
    @Test
    public void validResponseFormatDER() {
        // given
        final GenerateCsrCaRequest testClass = new GenerateCsrCaRequest();
        testClass.setKeyPair("signKey");
        testClass.setResponseFormat("DER");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertTrue(constraintViolations.isEmpty());
    }
    
    @Test
    public void validResponseFormatPEM() {
        // given
        final GenerateCsrCaRequest testClass = new GenerateCsrCaRequest();
        testClass.setKeyPair("signKey");
        testClass.setResponseFormat("PEM");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertTrue(constraintViolations.isEmpty());
    }
    
    @Test
    public void errorCertificateChainTooLong() {
        // given
        final String expectedMessage = "Invalid GenerateCsrCaRequest request with certificateChain too long.";
        final GenerateCsrCaRequest testClass = new GenerateCsrCaRequest();
        testClass.setKeyPair("signKey");
        List<String> certificateChainLong =  IntStream.range(0, 11).mapToObj(x -> "cert"+x).toList();
        testClass.setCertificateChain(certificateChainLong);
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

}
