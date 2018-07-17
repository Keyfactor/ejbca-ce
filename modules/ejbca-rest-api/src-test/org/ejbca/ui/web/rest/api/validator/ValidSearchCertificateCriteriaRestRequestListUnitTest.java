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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;

/**
 * A unit test class for annotation @ValidSearchCertificateCriteriaRestRequestList and its validator.
 *
 * @version $Id: ValidSearchCertificateCriteriaRestRequestListUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
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
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnEmptyValue() {
        // given
        final String expectedMessage = "Invalid criteria value, cannot be empty.";
        final TestClassForAnnotation testClass = new TestClassForAnnotation(new ArrayList<SearchCertificateCriteriaRestRequest>());
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldPassOnNormalValue() {
        // given
        final TestClassForAnnotation testClass = new TestClassForAnnotation(Collections.singletonList(new SearchCertificateCriteriaRestRequest()));
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.", 0, constraintViolations.size());
    }

    @Test
    public void validationShouldFailOn2QueryCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, multiple 'QUERY' properties are not allowed.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("QUERY").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("QUERY").build();
        final TestClassForAnnotation testClass = new TestClassForAnnotation(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1));
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one query allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn13StatusCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, 'STATUS' property repetition.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest3 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest4 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest5 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest6 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest7 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest8 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest9 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest10 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest11 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest12 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").build();
        final TestClassForAnnotation testClass = new TestClassForAnnotation(
                Arrays.asList(
                        querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1, querySearchCertificateCriteriaRestRequest2,
                        querySearchCertificateCriteriaRestRequest3, querySearchCertificateCriteriaRestRequest4, querySearchCertificateCriteriaRestRequest5,
                        querySearchCertificateCriteriaRestRequest6, querySearchCertificateCriteriaRestRequest7, querySearchCertificateCriteriaRestRequest8,
                        querySearchCertificateCriteriaRestRequest9, querySearchCertificateCriteriaRestRequest10, querySearchCertificateCriteriaRestRequest11,
                        querySearchCertificateCriteriaRestRequest12
                )
        );
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Up to 12 are allowed.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2ISSUED_DATEBeforeCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'ISSUED_DATE' with 'BEFORE' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("BEFORE").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("BEFORE").build();
        final TestClassForAnnotation testClass = new TestClassForAnnotation(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1));
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'BEFORE' 'ISSUED_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2ISSUED_DATEAfterCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'ISSUED_DATE' with 'AFTER' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("AFTER").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("AFTER").build();
        final TestClassForAnnotation testClass = new TestClassForAnnotation(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1));
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'AFTER' 'ISSUED_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2EXPIRE_DATEBeforeCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'EXPIRE_DATE' with 'BEFORE' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("BEFORE").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("BEFORE").build();
        final TestClassForAnnotation testClass = new TestClassForAnnotation(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1));
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'BEFORE' 'EXPIRE_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2EXPIRE_DATEAfterCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'EXPIRE_DATE' with 'AFTER' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("AFTER").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("AFTER").build();
        final TestClassForAnnotation testClass = new TestClassForAnnotation(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1));
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'AFTER' 'EXPIRE_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2REVOCATION_DATEBeforeCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'REVOCATION_DATE' with 'BEFORE' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("BEFORE").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("BEFORE").build();
        final TestClassForAnnotation testClass = new TestClassForAnnotation(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1));
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'BEFORE' 'REVOCATION_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2REVOCATION_DATEAfterCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'REVOCATION_DATE' with 'AFTER' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("AFTER").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("AFTER").build();
        final TestClassForAnnotation testClass = new TestClassForAnnotation(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1));
        // when
        final Set<ConstraintViolation<TestClassForAnnotation>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'AFTER' 'REVOCATION_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }
}
