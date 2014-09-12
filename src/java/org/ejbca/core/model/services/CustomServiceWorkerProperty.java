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
package org.ejbca.core.model.services;

import java.util.List;

/**
 * Helper class for rendering an UI for a custom service worker.
 * 
 * @version $Id$
 */
public class CustomServiceWorkerProperty {

    public static final int UI_TEXTINPUT  = 0;
    public static final int UI_SELECTONE  = 1;
    public static final int UI_BOOLEAN    = 2;
    public static final int UI_SELECTMANY = 3;

    private final String name;
    private final int type;
    private final List<String> options;
    private final List<String> optionTexts;
    private String value;
    
    /**
     * Construct a UI object with a list of options to choose from.
     * @param name The name of the property this object should map to.
     * @param type One of CustomServiceWorkerProperty.UI_* constants.
     * @param options Selectable options.
     * @param optionTexts Label of the options in the same order.
     * @param value The current value of this component.
     */
    public CustomServiceWorkerProperty(final String name, final int type, final List<String> options, final List<String> optionTexts, final String value) {
        this.name = name;
        this.type = type;
        this.options = options;
        this.optionTexts = optionTexts;
        this.value = value;
    }

    /**
     * Construct a simple UI object with free text or boolean value.
     * @param name The name of the property this object should map to.
     * @param type One of CustomServiceWorkerProperty.UI_* constants.
     * @param value The current value of this component.
     */
    public CustomServiceWorkerProperty(final String name, final int type, final String value) {
        this.name = name;
        this.type = type;
        this.options = null;
        this.optionTexts = null;
        this.value = value;
    }

    /** @return the current value of this property (as String) */
    public String getValue() {
        return value;
    }
    
    /** Set the current value of this property (as String) */
    public void setValue(String value) {
        if (value!=null) {
            value = value.trim();
        }
        this.value = value;
    }
    
    /** @return the current value of this component as a boolean. */
    public boolean getBooleanValue() {
        return Boolean.valueOf(getValue());
    }
    /** Set the current value of this component as a boolean. */
    public void setBooleanValue(final boolean value) {
        setValue(Boolean.valueOf(value).toString());
    }
    /** @return the current value of this component as a "select many" component. */
    public String[] getMultiValue() {
        return getValue().split(";");
    }
    /** Set the current value of this component as a "select many" component. */
    public void setMultiValue(final String[] values) {
        final StringBuilder sb = new StringBuilder();
        for (final String value : values) {
            if (sb.length()>0) {
                sb.append(';');
            }
            sb.append(value);
        }
        setValue(sb.toString());
    }

    /** @return the name of this property */
    public String getName() { return name; }
    /** @return one of the CustomPublisherProperty.UI_* constants */
    public int getType() { return type; }
    /** @return true if this is a free text input field. */
    public boolean isTypeText() { return type == UI_TEXTINPUT; }
    /** @return true if this is a boolean input field. */
    public boolean isTypeBoolean() { return type == UI_BOOLEAN; }
    /** @return true if this is a "select one" input field. */
    public boolean isTypeSelectOne() { return type == UI_SELECTONE; }
    /** @return true if this is a "select many" input field. */
    public boolean isTypeSelectMany() { return type == UI_SELECTMANY; }
    /** @return a List of values this property can have or null if this does not apply to the type */
    public List<String> getOptions() { return options; }
    /** @return a List of user-friendly texts corresponding to the values this property can have or null if this does not apply to the type */
    public List<String> getOptionTexts() { return optionTexts; }
}
