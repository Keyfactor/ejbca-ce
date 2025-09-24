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
import org.ejbca.ui.web.rest.api.io.request.AddEndEntityRestRequest;
import org.ejbca.ui.web.rest.api.io.request.EnrollCertificateWithEntityRestRequest;
import org.ejbca.ui.web.rest.api.io.request.TokenType;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ValidEnrollCertificateWithEntityRestRequestUnitTest {

    private static final Validator validator = Validation.byDefaultProvider().configure().
            messageInterpolator(new ParameterMessageInterpolator()).buildValidatorFactory().getValidator();

    @Test
    public void errorEmptyEntity() {
        // given
        final String expectedMessage = "Invalid EnrollCertificateWithEntityRestRequest content,end entity can not be null.";
        final EnrollCertificateWithEntityRestRequest testClass = new EnrollCertificateWithEntityRestRequest();

        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorEmptyRequest() {
        // given
        final String expectedMessage = "Invalid EnrollCertificateWithEntityRestRequest content,end certificate request can not be null or empty.";
        final EnrollCertificateWithEntityRestRequest testClass = new EnrollCertificateWithEntityRestRequest();
        AddEndEntityRestRequest entityRestRequest = getEndEntityRestRequest();
        testClass.setEndEntity(entityRestRequest);
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorEmptyType() {
        // given
        final String expectedMessage = "Invalid EnrollCertificateWithEntityRestRequest content, request type can not be null or empty.";
        final EnrollCertificateWithEntityRestRequest testClass = new EnrollCertificateWithEntityRestRequest();
        AddEndEntityRestRequest entityRestRequest = getEndEntityRestRequest();
        testClass.setEndEntity(entityRestRequest);
        testClass.setCertificateRequest("certreq");
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
        AddEndEntityRestRequest addEndEntityRestRequest = getEndEntityRestRequest();
        testClass.setEndEntity(addEndEntityRestRequest);
        testClass.setCertificateRequest("certreq");
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
        AddEndEntityRestRequest addEndEntityRestRequest = getEndEntityRestRequest();
        testClass.setEndEntity(addEndEntityRestRequest);
        testClass.setCertificateRequest("certreq");
        testClass.setCertificateRequestType("SPKAC");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(0, constraintViolations.size());
    }


    private static AddEndEntityRestRequest getEndEntityRestRequest() {
        AddEndEntityRestRequest entityRestRequest = new AddEndEntityRestRequest();
        entityRestRequest.setSubjectDn("CN=\"subjectDn\"");
        entityRestRequest.setCaName("CaName");
        entityRestRequest.setEndEntityProfileName("EndEntityProfileName");
        entityRestRequest.setCertificateProfileName("CertificateProfileName");
        entityRestRequest.setToken(TokenType.USERGENERATED.name());
        return entityRestRequest;
    }

}
