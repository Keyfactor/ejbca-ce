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
package org.ejbca.ui.web.admin.publisher;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Data class for custom publisher data used by edit publisher bean.
 *
 * @version $Id$
 */
public final class CustomPublisherMBData implements Serializable {

    private static final long serialVersionUID = 1L;

    // This will be used in the gui to guide the user that he/she has already set a password
    public static final String PASSWORD_PLACEHOLDER = "placeholder";

    private String customPublisherPropertyData;
    private String customPublisherCurrentClass;
    private Map<String, Object> customPublisherPropertyValues;

    public CustomPublisherMBData(final CustomPublisherContainer publisher) {
        initializeData(publisher);
    }

    public Map<String, Object> getCustomPublisherPropertyValues() {
        return customPublisherPropertyValues;
    }

    public String getCustomPublisherPropertyData() {
        return customPublisherPropertyData;
    }

    public void setCustomPublisherPropertyData(final String customPublisherPropertyData) {
        this.customPublisherPropertyData = customPublisherPropertyData;
    }

    public String getCustomPublisherCurrentClass() {
        return customPublisherCurrentClass;
    }

    public void setCustomPublisherCurrentClass(final String customPublisherCurrentClass) {
        this.customPublisherCurrentClass = customPublisherCurrentClass;
    }

    public void setCustomPublisherData(final CustomPublisherContainer publisher) throws PublisherException {
        publisher.setClassPath(customPublisherCurrentClass);
        if (publisher.isCustomUiRenderingSupported()) {
            final StringBuilder sb = new StringBuilder();
            for (final CustomPublisherProperty customPublisherProperty : publisher.getCustomUiPropertyList(EjbcaJSFHelper.getBean().getAdmin())) {
                final String name = customPublisherProperty.getName();
                final Object value = customPublisherPropertyValues.get(name);

                if (renderCustomCheckbox(customPublisherProperty)) {
                    sb.append(name).append('=').append((Boolean) value ? "true" : "false").append('\n');
                } else if (value != null) {
                    sb.append(name).append('=').append(provideFactualValue(customPublisherProperty, value)).append('\n');
                }
            }
            publisher.assignPropertyData(sb.toString());
        } else {
            publisher.assignPropertyData(customPublisherPropertyData);
        }
    }

    public List<SelectItem> getCustomPublisherPropertySelectOneMenuList(final CustomPublisherProperty customPublisherProperty) {
        final List<SelectItem> customPublisherPropertySelectOneMenuList = new ArrayList<>();
        for (int i = 0; i < customPublisherProperty.getOptions().size(); i++) {
            final String option = customPublisherProperty.getOptions().get(i);
            final String optionText = customPublisherProperty.getOptionTexts().get(i);
            customPublisherPropertySelectOneMenuList.add(new SelectItem(option, optionText));
        }
        return customPublisherPropertySelectOneMenuList;
    }

    public boolean renderCustomTextInput(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_TEXTINPUT;
    }

    public boolean renderCustomSelectOneMenu(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_SELECTONE;
    }

    public boolean renderCustomInputPassword(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_TEXTINPUT_PASSWORD;
    }

    public boolean renderCustomCheckbox(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_BOOLEAN;
    }

    public boolean renderCustomOutputTextArea(final CustomPublisherProperty customPublisherProperty) {
        return customPublisherProperty.getType() == CustomPublisherProperty.UI_TEXTOUTPUT;
    }
    
    private void initializeData(CustomPublisherContainer publisher) {
        customPublisherCurrentClass = publisher.getClassPath();
        customPublisherPropertyData = publisher.getPropertyData();

        final AuthenticationToken authenticationToken = EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject();

        customPublisherPropertyValues = new HashMap<>();
        for (final CustomPublisherProperty property : ((CustomPublisherContainer) publisher).getCustomUiPropertyList(authenticationToken)) {
            customPublisherPropertyValues.put(property.getName(), providePresentableValue(property));
        }
    }

    private Object provideFactualValue(CustomPublisherProperty property, Object presentableValue) {
        final boolean shouldProvideActualPasswordInsteadOfPlaceholder = renderCustomInputPassword(property)
                && PASSWORD_PLACEHOLDER.equals(presentableValue);

        return shouldProvideActualPasswordInsteadOfPlaceholder
                ? property.getValue()
                : presentableValue;
    }

    private String providePresentableValue(CustomPublisherProperty property) {
        final boolean shouldProvidePlaceholderInsteadOfPassword = renderCustomInputPassword(property)
                && !StringUtils.isBlank(property.getValue());

        return shouldProvidePlaceholderInsteadOfPassword
                ? PASSWORD_PLACEHOLDER
                : property.getValue();
    }
}
