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

import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.ui.web.rest.api.io.request.AddEndEntityRestRequest;
import org.ejbca.ui.web.rest.api.io.request.ExtendedInformationRestRequestComponent;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;

import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;

public class ValidAddEndEntityRestRequestUnitTest {

    private static final Validator validator = Validation.byDefaultProvider().configure().
        messageInterpolator(new ParameterMessageInterpolator()).buildValidatorFactory().getValidator();

    @Test
    public void errorSubjectDnMalformed() {
        // given
        final String expectedMessage = "Invalid AddEndEntityRestRequest content, subjectDn is malformed";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("something wrong");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorSubjectDnNull() {
        // Given
        final String expectedMessage = "Invalid AddEndEntityRestRequest content, subjectDn can not be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn(null);

        // When
        Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorSubjectDnEmpty() {
        // Given
        final String expectedMessage = "Invalid AddEndEntityRestRequest content, subjectDn can not be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("");

        // When
        Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorCaName() {
        // given
        final String expectedMessage = "Invalid AddEndEntityRestRequest content, caName can not be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorCertificateProfileName() {
        // given
        final String expectedMessage = "Invalid AddEndEntityRestRequest content, certificateProfileName can not be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorEndEntityProfileName() {
        // given
        final String expectedMessage = "Invalid AddEndEntityRestRequest content, endEntityProfileName can not be null or empty.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorToken() {
        // given
        final String expectedMessage = "Invalid AddEndEntityRestRequest content, token can not be null or empty.";
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
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorTokenType() {
        // given
        final String expectedMessage = "Invalid AddEndEntityRestRequest property, unrecognized token.";
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
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorStartTime() {
        // Given
        final String expectedMessage = "Invalid AddEndEntityRestRequest property, invalid date format.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("EndEntityProfileName");
        testClass.setToken("Token");
        testClass.setToken("P12");
        testClass.setStartTime("2019-01-41");

        // When
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorEndTime() {
        // Given
        final String expectedMessage = "Invalid AddEndEntityRestRequest property, invalid date format.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("EndEntityProfileName");
        testClass.setToken("Token");
        testClass.setToken("P12");
        testClass.setStartTime("2019-01-01");
        testClass.setStartTime("2020-01-41");

        // When
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorStatus() {
        final String expectedMessage = "Invalid AddEndEntityRestRequest property, unrecognized status.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("EndEntityProfileName");
        testClass.setToken("Token");
        testClass.setToken("P12");
        testClass.setStatus("BAD STATUS"); // for example: not REVOKED etc.

        // When
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorSerialNumber() {
        // Given
        final String expectedMessage = "Invalid SetEndEntityStatusRestRequest content, serial number is not valid Base64 formatted string.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("EndEntityProfileName");
        testClass.setToken("Token");
        testClass.setToken("P12");

        ExtendedInformationRestRequestComponent component = ExtendedInformationRestRequestComponent
                .builder().setName(ExtendedInformation.CERTIFICATESERIALNUMBER)
                .setValue("BadBASE64").build();
        testClass.setCustomData(List.of(component));

        // When
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorSequenceNumberLength() {
        // Given
        final String expectedMessage = "Invalid SetEndEntityStatusRestRequest content, sequence number should not be longer than 5 symbols.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("EndEntityProfileName");
        testClass.setToken("Token");
        testClass.setToken("P12");

        ExtendedInformationRestRequestComponent component = ExtendedInformationRestRequestComponent
                .builder().setName(ExtendedInformation.CERTIFICATESEQUENCENUMBER)
                .setValue("123456").build();
        testClass.setCustomData(List.of(component));

        // When
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorSequenceNumberFormat() {
        // Given
        final String expectedMessage = "Invalid SetEndEntityStatusRestRequest content, sequence number should be alphanumeric.";
        final AddEndEntityRestRequest testClass = new AddEndEntityRestRequest();
        testClass.setUsername("username");
        testClass.setSubjectDn("CN=abc");
        testClass.setCaName("caName");
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("EndEntityProfileName");
        testClass.setToken("Token");
        testClass.setToken("P12");

        ExtendedInformationRestRequestComponent component = ExtendedInformationRestRequestComponent
                .builder().setName(ExtendedInformation.CERTIFICATESEQUENCENUMBER)
                .setValue("1_BAD").build();
        testClass.setCustomData(List.of(component));

        // When
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);

        // Then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
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
