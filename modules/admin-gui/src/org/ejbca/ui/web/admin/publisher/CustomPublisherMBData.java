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
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Data class for custom publisher data used by edit publisher bean.
 * 
 * @version $Id$
 *
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
    
    public void setCustomPublisherData(final CustomPublisherContainer publisher) {
        publisher.setClassPath(customPublisherCurrentClass);
        if (publisher.isCustomUiRenderingSupported()) {
            final StringBuilder sb = new StringBuilder();
            for (final CustomPublisherProperty customPublisherProperty : publisher.getCustomUiPropertyList(EjbcaJSFHelper.getBean().getAdmin())) {
                if (customPublisherProperty.getType() == CustomPublisherProperty.UI_BOOLEAN) {
                    if (((Boolean)customPublisherPropertyValues.get(customPublisherProperty.getName()))) {
                        sb.append(customPublisherProperty.getName()).append('=').append("true").append('\n');
                    } else {
                        sb.append(customPublisherProperty.getName()).append('=').append("false").append('\n');
                    }
                } else {
                    if (customPublisherPropertyValues.get(customPublisherProperty.getName()) != null) {
                        // Save the actual password instead of placeholder.
                        if (customPublisherProperty.getType() == CustomPublisherProperty.UI_TEXTINPUT_PASSWORD && customPublisherPropertyValues.get(customPublisherProperty.getName()).equals(PASSWORD_PLACEHOLDER)) {
                            sb.append(customPublisherProperty.getName()).append('=')
                            .append(customPublisherProperty.getValue()).append('\n');
                            continue;
                        }
                        sb.append(customPublisherProperty.getName()).append('=')
                                .append(customPublisherPropertyValues.get(customPublisherProperty.getName())).append('\n');
                    }
                }
            }
            publisher.setPropertyData(sb.toString());
        } else {
            publisher.setPropertyData(customPublisherPropertyData);
        }
    }
    
    public List<SelectItem> getCustomPublisherPropertySelectOneMenuList(final CustomPublisherProperty customPublisherProperty) {
        final List<SelectItem> customPublisherPropertySelectOneMenuList = new ArrayList<>();
        for (int i=0; i < customPublisherProperty.getOptions().size(); i++) {
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
        customPublisherCurrentClass = ((CustomPublisherContainer) publisher).getClassPath();
        customPublisherPropertyData = ((CustomPublisherContainer) publisher).getPropertyData();

        customPublisherPropertyValues = new HashMap<>();

        for (final CustomPublisherProperty customPublisherProperty : ((CustomPublisherContainer) publisher)
                .getCustomUiPropertyList(EjbcaJSFHelper.getBean().getEjbcaWebBean().getAdminObject())) {
            if (customPublisherProperty.getType() == CustomPublisherProperty.UI_TEXTINPUT_PASSWORD && !StringUtils.isBlank(customPublisherProperty.getValue())) {
                customPublisherPropertyValues.put(customPublisherProperty.getName(), PASSWORD_PLACEHOLDER); // Should show a plcaeholder in gui instead of actual password!
                continue;
            }
            customPublisherPropertyValues.put(customPublisherProperty.getName(), customPublisherProperty.getValue());
        }
    }    
}
