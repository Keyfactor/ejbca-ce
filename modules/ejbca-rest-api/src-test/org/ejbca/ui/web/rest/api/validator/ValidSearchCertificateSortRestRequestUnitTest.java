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

import org.ejbca.ui.web.rest.api.io.request.SearchCertificateSortRestRequest;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.junit.Test;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Set;


import static org.junit.Assert.assertEquals;

/**
 * A unit test class for annotation @ValidSearchCertificateSortRestRequest and its validator.
 *
 * @version $Id: ValidSearchCertificateSortRestRequestUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
public class ValidSearchCertificateSortRestRequestUnitTest {

    private static final Validator validator = Validation.byDefaultProvider().configure().
        messageInterpolator(new ParameterMessageInterpolator()).buildValidatorFactory().getValidator();

    @Test
    public void validationShouldFailOnEmptyInvalidProperty() {
        // given
        final String expectedMessage = "Invalid search criteria sort property.";
        final SearchCertificateSortRestRequest testClass = SearchCertificateSortRestRequest.builder()
                .property("CA")
                .operation("DESC")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateSortRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }

    @Test
    public void validationShouldFailOnInvalidOperation() {
        // given
        final String expectedMessage = "Invalid search criteria sort operation.";
        final SearchCertificateSortRestRequest testClass = SearchCertificateSortRestRequest.builder()
                .property("USERNAME")
                .operation("DSC")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateSortRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Invalid object.",1, constraintViolations.size());
        assertEquals("Validation message should match.", expectedMessage, constraintViolations.iterator().next().getMessage());
    }
    
    @Test
    public void validationShouldPassOnSTATUSPropertyWithOperationASC() {
        // given
        final SearchCertificateSortRestRequest testClass = SearchCertificateSortRestRequest.builder()
                .property("STATUS")
                .operation("ASC")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateSortRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }
    
    @Test
    public void validationShouldPassOnISSUER_DNPropertyWithOperationASC() {
        // given
        final SearchCertificateSortRestRequest testClass = SearchCertificateSortRestRequest.builder()
                .property("ISSUER_DN")
                .operation("ASC")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateSortRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }

    @Test
    public void validationShouldPassOnSUBJECT_DNPropertyWithOperationASC() {
        // given
        final SearchCertificateSortRestRequest testClass = SearchCertificateSortRestRequest.builder()
                .property("SUBJECT_DN")
                .operation("ASC")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateSortRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }
    
    @Test
    public void validationShouldPassOnEND_ENTITY_PROFILEPropertyWithOperationASC() {
        // given
        final SearchCertificateSortRestRequest testClass = SearchCertificateSortRestRequest.builder()
                .property("END_ENTITY_PROFILE")
                .operation("ASC")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateSortRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }
    
    @Test
    public void validationShouldPassOnValidPropertyAndOperationWithSpace() {
        // given
        final SearchCertificateSortRestRequest testClass = SearchCertificateSortRestRequest.builder()
                .property(" END_ENTITY_PROFILE ")
                .operation(" ASC ")
                .build();
        // when
        final Set<ConstraintViolation<SearchCertificateSortRestRequest>> constraintViolations = validator.validate(testClass);
        // then
        assertEquals("Valid object.",0, constraintViolations.size());
    }
}
