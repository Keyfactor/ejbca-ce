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

import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.junit.Test;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;

/**
 * A unit test class for annotation @ValidSearchCertificateCriteriaRestRequestList and its validator.
 *
 * @version $Id: ValidSearchCertificateCriteriaRestRequestListUnitTest.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
public class ValidSearchCertificateCriteriaRestRequestListUnitTest {

    private static final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    // We create a simple class for testing to check that annotation triggers the validation and reports about a validation failure
    public class TestClassForAnnotation {

        @ValidSearchCertificateCriteriaRestRequestList
        private List<SearchCertificateCriteriaRestRequest> criteria;

        public TestClassForAnnotation(final List<SearchCertificateCriteriaRestRequest> criteria) {
            this.criteria = criteria;
        }
    }

    @Test
    public void validationShouldFailOnNullValue() {
        // given
        final String expectedMessage = "Invalid criteria value, cannot be null.";
        final TestClassForAnnotation testClass = new TestClassForAnnotation(null);
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnEmptyValue() {
        // given
        final String expectedMessage = "Invalid criteria value, cannot be empty.";
        final TestClassForAnnotation testClass = new TestClassForAnnotation(new ArrayList<SearchCertificateCriteriaRestRequest>());
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(1, constraintViolations.size());
        assertEquals(expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldPassOnNormalValue() {
        // given
        final TestClassForAnnotation testClass = new TestClassForAnnotation(Collections.singletonList(new SearchCertificateCriteriaRestRequest()));
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals(0, constraintViolations.size());
    }
}
