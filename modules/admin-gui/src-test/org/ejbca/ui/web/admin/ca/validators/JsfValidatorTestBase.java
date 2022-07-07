/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.ca.validators;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.same;
import static org.easymock.EasyMock.verify;

import java.util.HashMap;
import java.util.Map;

import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;

import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Before;

public class JsfValidatorTestBase {

    private final FacesContext fc = EasyMock.createStrictMock(FacesContext.class);
    private final UIComponent comp = EasyMock.createStrictMock(UIComponent.class);

    public JsfValidatorTestBase() {
        super();
    }

    protected FacesContext getMockedFacesContext() {
        return fc;
    }

    protected UIComponent getMockedUiComponent() {
        return comp;
    }

    @Before
    public void before() {
        final Map<String, Object> attributeMap = new HashMap<>();
        attributeMap.put("errorMessage", "SomeErrorMessage"); // Prevents call to EjbcaJSFHelper
        reset(fc, comp);
        expect(comp.getClientId(same(fc))).andReturn("TestDummy").anyTimes();
        expect(comp.getAttributes()).andReturn(attributeMap).anyTimes();
        replay(fc, comp);
    }

    @After
    public void after() {
        verify(fc, comp);
    }

}