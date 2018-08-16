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

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;

import org.apache.log4j.Logger;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificateCriteriaRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequestBuilder;
import org.junit.Test;

/**
 * A unit test class for annotation @ValidSearchCertificateCriteriaRestRequestList and its validator.
 * <br/>
 * <b>Note: </b> Due to test compilation issue ECA-7148, we use an original input class SearchCertificatesRestRequest instead of simplified annotated class.
 *
 * @version $Id: ValidSearchCertificateCriteriaRestRequestListUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class ValidSearchCertificateCriteriaRestRequestListUnitTest {
    private static Logger log = Logger.getLogger(ValidSearchCertificateCriteriaRestRequestListUnitTest.class);

    private static final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    public void validationShouldFailOnNullValue() {
        // given
        final String expectedMessage = "Invalid criteria value, cannot be null.";
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(null)
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnEmptyValue() {
        // given
        final String expectedMessage = "Invalid criteria value, cannot be empty.";
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(new ArrayList<SearchCertificateCriteriaRestRequest>())
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldPassOnNormalValue() {
        // given
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults().build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.", 0, constraintViolations.size());
    }

    @Test
    public void validationShouldFailOn2QueryCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, multiple 'QUERY' properties are not allowed.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("QUERY").value("TEST").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("QUERY").value("TEST").operation("EQUAL").build();
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one query allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn13StatusCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, 'STATUS' property repetition.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest2 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest3 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest4 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest5 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest6 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest7 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest8 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest9 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest10 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest11 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest12 = SearchCertificateCriteriaRestRequest.builder().property("STATUS").value("CERT_ACTIVE").operation("EQUAL").build();
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(
                        Arrays.asList(
                                querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1, querySearchCertificateCriteriaRestRequest2,
                                querySearchCertificateCriteriaRestRequest3, querySearchCertificateCriteriaRestRequest4, querySearchCertificateCriteriaRestRequest5,
                                querySearchCertificateCriteriaRestRequest6, querySearchCertificateCriteriaRestRequest7, querySearchCertificateCriteriaRestRequest8,
                                querySearchCertificateCriteriaRestRequest9, querySearchCertificateCriteriaRestRequest10, querySearchCertificateCriteriaRestRequest11,
                                querySearchCertificateCriteriaRestRequest12
                        )
                )
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        log.info(constraintViolations);
        assertEquals("Up to 12 are allowed.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2ISSUED_DATEBeforeCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'ISSUED_DATE' with 'BEFORE' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'BEFORE' 'ISSUED_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2ISSUED_DATEAfterCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'ISSUED_DATE' with 'AFTER' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("ISSUED_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();

        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'AFTER' 'ISSUED_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2EXPIRE_DATEBeforeCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'EXPIRE_DATE' with 'BEFORE' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'BEFORE' 'EXPIRE_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2EXPIRE_DATEAfterCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'EXPIRE_DATE' with 'AFTER' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("EXPIRE_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'AFTER' 'EXPIRE_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2REVOCATION_DATEBeforeCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'REVOCATION_DATE' with 'BEFORE' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("BEFORE").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'BEFORE' 'REVOCATION_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOn2REVOCATION_DATEAfterCriteria() {
        // given
        final String expectedMessage = "Invalid criteria value, overlapping properties 'REVOCATION_DATE' with 'AFTER' operation.";
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest0 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificateCriteriaRestRequest querySearchCertificateCriteriaRestRequest1 = SearchCertificateCriteriaRestRequest.builder().property("REVOCATION_DATE").operation("AFTER").value("2018-06-15T14:07:09Z").build();
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestBuilder.withDefaults()
                .criteria(Arrays.asList(querySearchCertificateCriteriaRestRequest0, querySearchCertificateCriteriaRestRequest1))
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Only one 'AFTER' 'REVOCATION_DATE' is allowed at a time.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }
}
