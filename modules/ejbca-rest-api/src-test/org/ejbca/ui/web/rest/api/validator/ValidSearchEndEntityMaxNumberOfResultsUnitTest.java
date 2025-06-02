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

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import jakarta.validation.ConstraintValidatorContext;

public class ValidSearchEndEntityMaxNumberOfResultsUnitTest {

    private ConstraintValidatorContext constraintValidatorContextMock;
    private ConstraintValidatorContext.ConstraintViolationBuilder constraintViolationBuilderMock;
    private ValidSearchEndEntityMaxNumberOfResults.Validator validator;

    @Before
    public void setUp() throws Exception {
        constraintValidatorContextMock = createNiceMock(ConstraintValidatorContext.class);
        constraintViolationBuilderMock = createMock(ConstraintValidatorContext.ConstraintViolationBuilder.class);
        replay();
        validator = new ValidSearchEndEntityMaxNumberOfResults.Validator();
    }

    @Test
    public void validationShouldFailOnNullValue() {
        // given
        final String expectedMessage = "{ValidSearchEndEntityMaxNumberOfResults.invalid.null}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage))
                .andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        Integer maxNumberOfResults = null;
        // when
        boolean valid = validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        assertFalse(valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOnNegativeValue() {
        // given
        final String expectedMessage = "{ValidSearchEndEntityMaxNumberOfResults.invalid.lessThanOrEqualNull}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage))
                .andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        Integer maxNumberOfResults = -1;
        // when
        boolean valid = validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        assertFalse(valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOnZeroValue() {
        // given
        final String expectedMessage = "{ValidSearchEndEntityMaxNumberOfResults.invalid.lessThanOrEqualNull}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage))
                .andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        Integer maxNumberOfResults = 0;
        // when
        boolean valid = validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        assertFalse(valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOnValueAboveMaximum() {
        // given
        final String expectedMessage = "{ValidSearchEndEntityMaxNumberOfResults.invalid.moreThanMaximum}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage))
                .andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        Integer maxNumberOfResults = 1001;
        // when
        boolean valid = validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        assertFalse(valid);
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldPassOnNormalValue() {
        // given
        //      replay(globalCesecoreConfigurationMock);
        Integer maxNumberOfResults = 201;
        // when
        boolean valid = validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        assertTrue("Validation should pass", valid);
    }
}
