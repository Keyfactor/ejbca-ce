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
package org.ejbca.ui.web.rest.api.resource.validator;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.rest.api.io.request.AddEndEntityRestRequest;
import org.junit.Test;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.util.Set;

import static org.junit.Assert.assertEquals;

public class AddEndEntityRestRequestValidatorUnitTest {
    private static Logger log = Logger.getLogger(AddEndEntityRestRequestValidatorUnitTest.class);

    private static final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    public void errorUsername() {
        // given
        final String expectedMessage = "Invalid add end entity content, username cannot be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals( expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorSubjectDn() {
        // given
        final String expectedMessage = "Invalid add end entity content, subjectDn cannot be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("something wrong");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals( expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorCaName() {
        // given
        final String expectedMessage = "Invalid add end entity content, caName cannot be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals( expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorCertificateProfileName() {
        // given
        final String expectedMessage = "Invalid add end entity content, certificateProfileName cannot be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals( expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorEndEntityProfileName() {
        // given
        final String expectedMessage = "Invalid add end entity content, endEntityProfileName cannot be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals( expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorToken() {
        // given
        final String expectedMessage = "Invalid add end entity content, token cannot be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("EndEntityProfileName");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals( expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorTokenType() {
        // given
        final String expectedMessage = "Invalid add end entity property, unrecognized token.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("EndEntityProfileName");
        testClass.setToken("Token");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals( expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void okRequest() {
        // given
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("EndEntityProfileName");
        testClass.setToken("P12");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(0, constraintViolations.size());
    }

}
