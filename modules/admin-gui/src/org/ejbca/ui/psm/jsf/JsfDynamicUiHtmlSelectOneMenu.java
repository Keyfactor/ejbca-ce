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
package org.ejbca.ui.psm.jsf;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import jakarta.faces.component.UISelectItems;
import jakarta.faces.component.html.HtmlSelectOneMenu;
import jakarta.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.util.ui.DynamicUiComponent;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * MyFaces HTML UI drop-down box for component implementing the {@link PropertyChangeListener} interface 
 * to get noticed for dynamic UI property changes.
 */
public class JsfDynamicUiHtmlSelectOneMenu extends HtmlSelectOneMenu implements DynamicUiComponent, PropertyChangeListener {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(JsfDynamicUiHtmlSelectOneMenu.class);

    /** DynamicUIProperty reference. */
    private DynamicUiProperty<?> dynamicUiProperty;

    /**
     * Default constructor.
     */
    public JsfDynamicUiHtmlSelectOneMenu() {
    }

    /**
     * Sets the dynamic UI property reference.
     * @param property the dynamic UI property.
     */
    void setDynamicUiProperty(final DynamicUiProperty<?> property) {
        this.dynamicUiProperty = property;
        this.dynamicUiProperty.addDynamicUiComponent(this);
    }
    
    @Override
    public void updateValueRange() {
        final List<SelectItem> items = new ArrayList<>();
        if (dynamicUiProperty != null) {
            if (dynamicUiProperty.isI18NLabeled()) {
                final Map<?, String> labels = dynamicUiProperty.getLabels();
                for (Entry<?, String> entry : labels.entrySet()) {
                    items.add(new SelectItem(entry.getKey(), EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(entry.getValue())));
                    
                }
            } else {
                final Collection<String> entries = dynamicUiProperty.getPossibleValuesAsStrings();
                for (String entry : entries) {
                    items.add(new SelectItem(entry,entry));
                }
            }
            final UISelectItems selectItems = new UISelectItems();
            selectItems.setValue(items);
            getChildren().clear();
            getChildren().add(selectItems);
        }
    }

    @Override
    public void propertyChange(final PropertyChangeEvent event) {
        if (log.isTraceEnabled()) {
            log.trace("Property change event for dynamic UI property " + (dynamicUiProperty != null ? dynamicUiProperty.getName()
                    : null) + " fired: " + event);
        }
        if (event.getOldValue() != event.getNewValue()) {
            setValue(event.getNewValue());
        }
    }
}
