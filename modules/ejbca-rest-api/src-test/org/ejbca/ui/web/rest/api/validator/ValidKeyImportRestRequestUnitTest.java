package org.ejbca.ui.web.rest.api.validator;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.ejbca.ui.web.rest.api.io.request.KeyImportRestRequest;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Set;

import static org.junit.Assert.assertEquals;

public class ValidKeyImportRestRequestUnitTest {

    private static final Validator validator = Validation.byDefaultProvider().configure().
            messageInterpolator(new ParameterMessageInterpolator()).buildValidatorFactory().getValidator();

    @Test
    public void errorCertificateProfileName() {
        // given
        final String expectedMessage = "Invalid KeyImportRestRequest content, certificateProfileName cannot be null or empty.";
        final KeyImportRestRequest testClass = new KeyImportRestRequest();
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorEndEntityProfileName() {
        // given
        final String expectedMessage = "Invalid KeyImportRestRequest content, endEntityProfileName cannot be null or empty.";
        final KeyImportRestRequest testClass = new KeyImportRestRequest();
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("");
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void errorEmptyKeystores() {
        // given
        final String expectedMessage = "Invalid KeyImportRestRequest content, keystores cannot be null or empty.";
        final KeyImportRestRequest testClass = new KeyImportRestRequest();
        testClass.setCertificateProfileName("CertificateProfileName");
        testClass.setEndEntityProfileName("endEntityProfileName");
        testClass.setKeystores(new ArrayList<>());
        // when
        final Set<ConstraintViolation<Object>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }
}
