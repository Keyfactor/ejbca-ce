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

import org.junit.Before;
import org.junit.Test;
import org.powermock.api.easymock.PowerMock;

import javax.faces.component.UIComponent;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import java.util.HashMap;
import java.util.Map;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * A unit test for Validation Helper.
 *
 * @version $Id$
 */
public class ValidationHelperUnitTest {

    // Mocks
    private FacesContext facesContext;
    private ExternalContext externalContext;
    private UIComponent uiComponent;
    //
    private Map<String, Object> attributesMap;
    private Map<String, String[]> requestParameterValuesMap;

    @Before
    public void setUp() throws Exception {
        //
        attributesMap = new HashMap<>();
        requestParameterValuesMap = new HashMap<>();
        // Mock all static methods of FacesContext using PowerMockito
        PowerMock.mockStatic(FacesContext.class);
        // Create mocks
        facesContext = createMock(FacesContext.class);
        externalContext = createMock(ExternalContext.class);
        uiComponent = createMock(UIComponent.class);
        // Setup mocks calls
        expect(facesContext.getExternalContext()).andReturn(externalContext);
        expect(externalContext.getRequestParameterValuesMap()).andReturn(requestParameterValuesMap);
        expect(uiComponent.getAttributes()).andReturn(attributesMap).times(1, 2); // attributes: validationCondition, validationTriggerIds
        // Replay Easymocks
        replay(facesContext);
        replay(externalContext);
        replay(uiComponent);
    }

    @Test
    public void matchConditionalValidationReturnTrueIfNoConditions() {
        // when
        final boolean actualResult = ValidationHelper.matchConditionalValidation(facesContext, uiComponent);
        // then
        assertTrue("matchConditionalValidation(...) should return true by default.", actualResult);
        verify(uiComponent);
    }

    @Test
    public void matchConditionalValidationReturnTrueIfValidationCondition() {
        // given
        attributesMap.put("validationCondition", "true");
        // when
        final boolean actualResult = ValidationHelper.matchConditionalValidation(facesContext, uiComponent);
        // then
        assertTrue("matchConditionalValidation(...) should return true for validationCondition=\"true\".", actualResult);
        verify(uiComponent);
    }

    @Test
    public void matchConditionalValidationReturnFalseIfValidationCondition() {
        // given
        attributesMap.put("validationCondition", "false");
        // when
        final boolean actualResult = ValidationHelper.matchConditionalValidation(facesContext, uiComponent);
        // then
        assertFalse("matchConditionalValidation(...) should return true for validationCondition=\"false\".", actualResult);
        verify(uiComponent);
    }

    @Test
    public void matchConditionalValidationReturnTrueIfValidationTriggerIdsMatchesSingleButtonIdByFullKey() {
        // given
        attributesMap.put("validationTriggerIds", "someButtonId");
        requestParameterValuesMap.put("someButtonId", new String[]{"Some Button"});
        // when
        final boolean actualResult = ValidationHelper.matchConditionalValidation(facesContext, uiComponent);
        // then
        assertTrue("matchConditionalValidation(...) should return true for validationTriggerIds=\"someButtonId\" by full key.", actualResult);
        verify(uiComponent);
        verify(externalContext);
    }

    @Test
    public void matchConditionalValidationReturnTrueIfValidationTriggerIdsMatchesSingleButtonIdByShortKey() {
        // given
        attributesMap.put("validationTriggerIds", "someButtonId");
        requestParameterValuesMap.put("someForm:someButtonId", new String[]{"Some Button"});
        // when
        final boolean actualResult = ValidationHelper.matchConditionalValidation(facesContext, uiComponent);
        // then
        assertTrue("matchConditionalValidation(...) should return true for validationTriggerIds=\"someButtonId\" by short key.", actualResult);
        verify(uiComponent);
        verify(externalContext);
    }

    @Test
    public void matchConditionalValidationReturnFalseIfValidationTriggerIdsDidntMatch() {
        // given
        attributesMap.put("validationTriggerIds", "someButtonId");
        requestParameterValuesMap.put("someOtherButtonId", new String[]{"Some Other Button"});
        // when
        final boolean actualResult = ValidationHelper.matchConditionalValidation(facesContext, uiComponent);
        // then
        assertFalse("matchConditionalValidation(...) should return false for validationTriggerIds=\"someButtonId\".", actualResult);
        verify(uiComponent);
        verify(externalContext);
    }

}
