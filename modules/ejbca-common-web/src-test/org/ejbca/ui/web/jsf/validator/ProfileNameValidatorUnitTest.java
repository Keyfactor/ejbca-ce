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

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;

import java.util.HashMap;
import java.util.Map;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

/**
 * A unit test for JSF validator.
 *
 */
public class ProfileNameValidatorUnitTest {

    private final ProfileNameValidator testClass = new ProfileNameValidator();
    // Mocks
    private FacesContext facesContext;
    private UIComponent uiComponent;
    //
    private Map<String, Object> attributesMap;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        //
        attributesMap = new HashMap<>();
        // Create mocks
        facesContext = EasyMock.createStrictMock(FacesContext.class);
        uiComponent = EasyMock.createStrictMock(UIComponent.class);
        // Setup mocks calls
        expect(uiComponent.getAttributes()).andReturn(attributesMap).times(0, 3); // attributes: validationCondition, validationTriggerIds, maximumLength
        // Replay Easymocks
        replay(facesContext);
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
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(uiComponent);
    }

    @Test
    public void failOnEmptyProfileName() {
        // given
        final String profileName = " ";
        expectedException.expect(NullPointerException.class); //NullPointerException thrown when trying to get message text
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(facesContext);
    }

    @Test
    public void failOnIllegalCharactersInProfileName() {
        // given
        final String profileName = "I_AM_INVALID!";
        expectedException.expect(NullPointerException.class); //NullPointerException thrown when trying to get message text
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(facesContext);
    }

    @Test
    public void failOnProfileNameOverMaximumLengthLimit() {
        // given
        final String profileName = "I_AM_VALID_BUT_LONG"; // Length 19
        attributesMap.put("maximumLength", "10");
        expectedException.expect(NullPointerException.class); //NullPointerException thrown when trying to get message text
        // when
        testClass.validate(facesContext, uiComponent, profileName);
        // then
        verify(facesContext);
        verify(uiComponent);
    }

}
