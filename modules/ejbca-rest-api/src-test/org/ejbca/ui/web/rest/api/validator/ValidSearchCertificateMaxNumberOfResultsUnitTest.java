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

import org.cesecore.config.GlobalCesecoreConfiguration;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

import jakarta.validation.ConstraintValidatorContext;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertTrue;

/**
 * A unit test class for annotation @ValidSearchCertificateMaxNumberOfResults and its validator.
 * <br/>
 * <b>Note: </b> Due to test compilation issue ECA-7148, we use an original input class SearchCertificatesRestRequest instead of simplified annotated class.
 */
public class ValidSearchCertificateMaxNumberOfResultsUnitTest {

    private ConstraintValidatorContext constraintValidatorContextMock;
    private ConstraintValidatorContext.ConstraintViolationBuilder constraintViolationBuilderMock;
    private ValidSearchCertificateMaxNumberOfResults.Validator validator;
    GlobalCesecoreConfiguration globalCesecoreConfigurationMock;

    @Before
    public void setUp() throws Exception {
        globalCesecoreConfigurationMock = createMock(GlobalCesecoreConfiguration.class);
        constraintValidatorContextMock = createNiceMock(ConstraintValidatorContext.class);
        constraintViolationBuilderMock = createMock(ConstraintValidatorContext.ConstraintViolationBuilder.class);
        EasyMock.expect(globalCesecoreConfigurationMock
                        .getMaximumQueryCount())
                .andReturn(321).anyTimes();

        replay();
        validator = new ValidSearchCertificateMaxNumberOfResults.Validator();
        validator.globalCesecoreConfiguration = globalCesecoreConfigurationMock;
    }

    @Test
    public void validationShouldFailOnNullValue() {
        // given
        final String expectedMessage = "{ValidSearchCertificateMaxNumberOfResults.invalid.null}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        replay(globalCesecoreConfigurationMock);
        Integer maxNumberOfResults = null;
        // when
        boolean valid = validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOnNegativeValue() {
        // given
        final String expectedMessage = "{ValidSearchCertificateMaxNumberOfResults.invalid.lessThanOrEqualNull}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        replay(globalCesecoreConfigurationMock);
        Integer maxNumberOfResults = -1;
        // when
        validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOnZeroValue() {
        // given
        final String expectedMessage = "{ValidSearchCertificateMaxNumberOfResults.invalid.lessThanOrEqualNull}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        replay(globalCesecoreConfigurationMock);
        Integer maxNumberOfResults = 0;
        // when
        validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldFailOnValueAboveMaximum() {
        // given
        final String expectedMessage = "{ValidSearchCertificateMaxNumberOfResults.invalid.moreThanMaximum}";
        EasyMock.expect(constraintValidatorContextMock.buildConstraintViolationWithTemplate(expectedMessage)).andReturn(constraintViolationBuilderMock).once();
        replay(constraintValidatorContextMock);
        replay(globalCesecoreConfigurationMock);
        Integer maxNumberOfResults = 401;
        // when
        validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        verify(constraintValidatorContextMock);
    }

    @Test
    public void validationShouldPassOnNormalValue() {
        // given
        replay(globalCesecoreConfigurationMock);
        Integer maxNumberOfResults = 201;
        // when
        boolean valid = validator.isValid(maxNumberOfResults, constraintValidatorContextMock);
        // then
        assertTrue("Validation should pass", valid);
    }
}
