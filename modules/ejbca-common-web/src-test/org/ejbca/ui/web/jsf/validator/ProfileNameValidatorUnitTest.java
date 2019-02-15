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
package org.ejbca.ui.web.jsf.validator;

import org.cesecore.util.StringTools;
import org.ejbca.ui.web.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.faces.application.Application;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.validator.ValidatorException;

import java.util.HashMap;
import java.util.Map;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

/**
 * A unit test for JSF validator.
 *
 * @version $Id: ProfileNameValidatorUnitTest.java 29504 2018-07-17 17:55:12Z andrey_s_helmes $
 */
@PrepareForTest({StringTools.class, FacesContext.class })
@RunWith(PowerMockRunner.class)
public class ProfileNameValidatorUnitTest {

    private final ProfileNameValidator testClass = new ProfileNameValidator();
    // Mocks
    private FacesContext facesContext;
    private Application application;
    private EjbcaJSFHelper ejbcaJSFHelper;
    private EjbcaWebBean ejbcaWebBean;
    private UIComponent uiComponent;
    //
    private Map<String, Object> attributesMap;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        //
        attributesMap = new HashMap<>();
        // Mock all static methods of FacesContext and StringTools using PowerMockito
        PowerMock.mockStatic(FacesContext.class);
        PowerMock.mockStatic(StringTools.class);
        // Create mocks
        facesContext = createMock(FacesContext.class);
        application = createMock(Application.class);
        ejbcaJSFHelper = createMock(EjbcaJSFHelper.class);
        ejbcaWebBean = createMock(EjbcaWebBean.class);
        uiComponent = createMock(UIComponent.class);
        // Setup mocks calls
        expect(FacesContext.getCurrentInstance()).andReturn(facesContext);
        expect(facesContext.getApplication()).andReturn(application);
        expect(application.evaluateExpressionGet(facesContext, "#{web}", EjbcaJSFHelper.class)).andReturn(ejbcaJSFHelper);
        expect(ejbcaJSFHelper.getEjbcaWebBean()).andReturn(ejbcaWebBean);
        expect(uiComponent.getAttributes()).andReturn(attributesMap).times(0, 3); // attributes: validationCondition, validationTriggerIds, maximumLength
        // Replay Easymocks
        replay(facesContext);
        replay(application);
        replay(ejbcaJSFHelper);
        replay(uiComponent);
    }

    @Test
    public void passNullProfileName() {
        // when
        testClass.validate(facesContext, uiComponent, null);
    }

    @Test
    public void passOnPreconditionsFalse() {
        // given
        final String profileName = "I_AM_IGNORED";
        attributesMap.put("validationCondition", "false");
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(uiComponent);
    }

    @Test
    public void passOnValidProfileNameWithoutMaximumLengthAttribute() {
        // given
        final String profileName = "I_AM_VALID";
        attributesMap = null;
        expect(StringTools.checkFieldForLegalChars(profileName)).andReturn(true);
        PowerMock.replay(StringTools.class);
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(uiComponent);
    }

    @Test
    public void passOnValidProfileNameWithMaximumLengthAttribute() {
        // given
        final String profileName = "I_AM_VALID"; // Length 10
        attributesMap.put("maximumLength", "11");
        expect(StringTools.checkFieldForLegalChars(profileName)).andReturn(true);
        PowerMock.replay(StringTools.class);
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(uiComponent);
    }

    @Test
    public void failOnEmptyProfileName() {
        // given
        final String profileName = " ";
        expect(ejbcaWebBean.getText("NAME_CANNOT_BE_EMPTY")).andReturn("Error message");
        replay(ejbcaWebBean);
        expectedException.expect(ValidatorException.class);
        expectedException.expectMessage("Error message");
        PowerMock.replay(FacesContext.class);
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(facesContext);
        verify(application);
        verify(ejbcaJSFHelper);
        verify(ejbcaWebBean);
    }

    @Test
    public void failOnIllegalCharactersInProfileName() {
        // given
        final String profileName = "I_AM_INVALID";
        expect(StringTools.checkFieldForLegalChars(profileName)).andReturn(false);
        expect(ejbcaWebBean.getText("ONLYCHARACTERS")).andReturn("Error message");
        replay(ejbcaWebBean);
        expectedException.expect(ValidatorException.class);
        expectedException.expectMessage("Error message");
        PowerMock.replay(FacesContext.class);
        PowerMock.replay(StringTools.class);
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(facesContext);
        verify(application);
        verify(ejbcaJSFHelper);
        verify(ejbcaWebBean);
    }

    @Test
    public void failOnProfileNameOverMaximumLengthLimit() {
        // given
        final String profileName = "I_AM_INVALID"; // Length 12
        attributesMap.put("maximumLength", "10");
        expect(StringTools.checkFieldForLegalChars(profileName)).andReturn(true);
        expect(ejbcaWebBean.getText("MAXIMUMLENGTH_FIELD", false, 10)).andReturn("Error message 10");
        replay(ejbcaWebBean);
        expectedException.expect(ValidatorException.class);
        expectedException.expectMessage("Error message 10");
        PowerMock.replay(FacesContext.class);
        PowerMock.replay(StringTools.class);
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(facesContext);
        verify(application);
        verify(ejbcaJSFHelper);
        verify(ejbcaWebBean);
        verify(uiComponent);
    }

}
