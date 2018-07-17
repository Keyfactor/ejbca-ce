/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.validator;

import org.junit.Test;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.util.Set;

import static org.junit.Assert.assertEquals;

/**
 * A unit test class for annotation @ValidSearchCertificateMaxNumberOfResults and its validator.
 *
 * @version $Id: ValidSearchCertificateMaxNumberOfResultsUnitTest.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
public class ValidSearchCertificateMaxNumberOfResultsUnitTest {

    private static final Validator validator =  Validation.buildDefaultValidatorFactory().getValidator();

    // We create a simple class for testing to check that annotation triggers the validation and reports about a validation failure
    public class TestClassForAnnotation {

        @ValidSearchCertificateMaxNumberOfResults
        private Integer maxNumberOfResults;

        public TestClassForAnnotation(final Integer maxNumberOfResults) {
            this.maxNumberOfResults = maxNumberOfResults;
        }
    }

    @Test
    public void validationShouldFailOnNullValue() {
        // given
        final String expectedMessage = "Invalid maximum number of results, cannot be null.";
        final TestClassForAnnotation testClass = new TestClassForAnnotation(null);
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.", 1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnNegativeValue() {
        // given
        final String expectedMessage = "Invalid maximum number of results, cannot be less or equal to zero.";
        final TestClassForAnnotation testClass = new TestClassForAnnotation(-1);
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.", 1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnZeroValue() {
        // given
        final String expectedMessage = "Invalid maximum number of results, cannot be less or equal to zero.";
        final TestClassForAnnotation testClass = new TestClassForAnnotation(0);
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.", 1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnValueAboveMaximum() {
        // given
        final String expectedMessage = "Invalid maximum number of results, cannot be more than 400.";
        final TestClassForAnnotation testClass = new TestClassForAnnotation(401);
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.", 1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldPassOnNormalValue() {
        // given
        final TestClassForAnnotation testClass = new TestClassForAnnotation(201);
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.", 0, constraintViolations.size());
    }
}
