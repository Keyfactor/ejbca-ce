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

import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;

import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.easymock.EasyMock;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.rest.api.builder.SearchCertificatesRestRequestTestBuilder;
import org.ejbca.ui.web.rest.api.io.request.SearchCertificatesRestRequest;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import static org.junit.Assert.assertEquals;

/**
 * A unit test class for annotation @ValidSearchCertificateMaxNumberOfResults and its validator.
 * <br/>
 * <b>Note: </b> Due to test compilation issue ECA-7148, we use an original input class SearchCertificatesRestRequest instead of simplified annotated class.
 */
@Ignore
@RunWith(PowerMockRunner.class)
@PrepareForTest({EjbLocalHelper.class})
public class ValidSearchCertificateMaxNumberOfResultsUnitTest {

    private static final Validator validator =  Validation.buildDefaultValidatorFactory().getValidator();

    @Before
    public void setUp() throws Exception {
        EjbLocalHelper ejbLocalHelperMock = EasyMock.createMock(EjbLocalHelper.class);
        GlobalConfigurationSessionLocal globalConfigurationSession = EasyMock.mock(GlobalConfigurationSessionLocal.class);
        GlobalCesecoreConfiguration globalCesecoreConfigurationMock = EasyMock.mock(GlobalCesecoreConfiguration.class);

        PowerMock.expectNew(EjbLocalHelper.class)
            .andReturn(ejbLocalHelperMock);
        EasyMock.expect(ejbLocalHelperMock.getGlobalConfigurationSession())
            .andReturn(globalConfigurationSession);
        EasyMock.expect(globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID))
            .andReturn(globalCesecoreConfigurationMock);
        EasyMock.expect(globalCesecoreConfigurationMock
            .getMaximumQueryCount())
            .andReturn(321);

        PowerMock.replay(EjbLocalHelper.class);
        EasyMock.replay();

    }

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
        final String expectedMessage = "Invalid maximum number of results, cannot be more than 321.";
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
