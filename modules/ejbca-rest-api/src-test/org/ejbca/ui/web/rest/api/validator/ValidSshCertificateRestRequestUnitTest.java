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
import org.ejbca.ui.web.rest.api.io.request.SshCertificateRequestRestRequest;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class ValidSshCertificateRestRequestUnitTest {
    private static final Validator validator = Validation.byDefaultProvider().configure().
            messageInterpolator(new ParameterMessageInterpolator()).buildValidatorFactory().getValidator();

    @Test
    public void errorNullPublicKey() {
        // given
        final String expectedMessage = "Invalid ValidSshCertificateRestRequest public key can not be null or empty.";
        final SshCertificateRequestRestRequest testClass = new SshCertificateRequestRestRequest();

        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorEmptyMandatoryField() {
        // given
        final String expectedMessage = "Invalid ValidSshCertificateRestRequest key id can not be null or empty.";
        final SshCertificateRequestRestRequest testClass = new SshCertificateRequestRestRequest();
        testClass.setPublicKey("My public key");

        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorEndEntityProfileEmpty() {
        // given
        final String expectedMessage = "Invalid ValidSshCertificateRestRequest end entity profile can not be null or empty.";
        final SshCertificateRequestRestRequest testClass = new SshCertificateRequestRestRequest();
        testClass.setPublicKey("My public key");
        testClass.setKeyId("My key Id");

        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorUsernameEmpty() {
        // given
        final String expectedMessage = "Invalid ValidSshCertificateRestRequest username can not be null or empty.";
        final SshCertificateRequestRestRequest testClass = new SshCertificateRequestRestRequest();
        testClass.setPublicKey("My public key");
        testClass.setKeyId("My key Id");
        testClass.setEndEntityProfile("My EEP");
        testClass.setUsername(" ");

        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorPasswordEmpty() {
        // given
        final String expectedMessage = "Invalid ValidSshCertificateRestRequest password can not be null or empty.";
        final SshCertificateRequestRestRequest testClass = new SshCertificateRequestRestRequest();
        testClass.setPublicKey("My public key");
        testClass.setKeyId("My key Id");
        testClass.setEndEntityProfile("My EEP");
        testClass.setUsername("My username");

        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }
    @Test
    public void okRequest() {
        // given
        final String expectedMessage = "Invalid ValidSshCertificateRestRequest password can not be null or empty.";
        final SshCertificateRequestRestRequest testClass = new SshCertificateRequestRestRequest();
        testClass.setPublicKey("My public key");
        testClass.setKeyId("My key Id");
        testClass.setEndEntityProfile("My EEP");
        testClass.setUsername("My username");
        testClass.setPassword("My password");

        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(0, constraintViolations.size());
    }


}
