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

import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;

import org.ejbca.ui.web.rest.api.builder.SearchCertificatesRestRequestTestBuilder;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * A unit test class for annotation @ValidSearchCertificateMaxNumberOfResults and its validator.
 * <br/>
 * <b>Note: </b> Due to test compilation issue ECA-7148, we use an original input class SearchCertificatesRestRequest instead of simplified annotated class.
 *
 * @version $Id: ValidSearchCertificateMaxNumberOfResultsUnitTest.java 29436 2018-07-03 11:12:13Z andrey_s_helmes $
 */
public class ValidSearchCertificateMaxNumberOfResultsUnitTest {

    private static final Validator validator =  Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    public void validationShouldFailOnNullValue() {
        // given
        final String expectedMessage = "Invalid maximum number of results, cannot be null.";
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestTestBuilder.withDefaults()
                .maxNumberOfResults(null)
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.", 1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnNegativeValue() {
        // given
        final String expectedMessage = "Invalid maximum number of results, cannot be less or equal to zero.";
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestTestBuilder.withDefaults().maxNumberOfResults(-1).build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.", 1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnZeroValue() {
        // given
        final String expectedMessage = "Invalid maximum number of results, cannot be less or equal to zero.";
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestTestBuilder.withDefaults().maxNumberOfResults(0).build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.", 1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnValueAboveMaximum() {
        // given
        final String expectedMessage = "Invalid maximum number of results, cannot be more than 400.";
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestTestBuilder.withDefaults().maxNumberOfResults(401).build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.", 1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldPassOnNormalValue() {
        // given
        final SearchCertificatesRestRequest testClass = SearchCertificatesRestRequestTestBuilder.withDefaults().maxNumberOfResults(201).build();
        // when
        final Set<ConstraintViolation<SearchCertificatesRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.", 0, constraintViolations.size());
    }
}
