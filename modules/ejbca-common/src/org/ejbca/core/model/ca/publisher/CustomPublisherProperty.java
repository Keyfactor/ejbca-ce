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
package org.ejbca.core.model.ca.publisher;

import java.util.List;

/**
 * Helper class for UIs that want to present a nice view of the configurable properties of a Custom Publisher.
 * 
 * All properties are interpreted as String values.
 * 
 * @version $Id$
 */
public class CustomPublisherProperty {

    public static final int UI_TEXTINPUT = 0;
    public static final int UI_SELECTONE = 1;
    public static final int UI_BOOLEAN   = 2;
    public static final int UI_TEXTOUTPUT = 3;
    public static final int UI_TEXTINPUT_PASSWORD = 3;

    private final String name;
    private final int type;
    private final List<String> options;
    private final List<String> optionTexts;
    String value;
    
    /**
     * Representation of a property where the user can select from a list of choices.
     *  
     * @param name name of the property
     * @param type one of CustomPublisherProperty.UI_* constants (only UI_SELECTONE makes sense in the current implementation)
     * @param options a list of selectable values
     * @param optionTexts a list of tests to apply to show the user for each of selectable values
     * @param value the current value of this property
     */
    public CustomPublisherProperty(final String name, final int type, final List<String> options, final List<String> optionTexts, final String value) {
        this.name = name;
        this.type = type;
        this.options = options;
        this.optionTexts = optionTexts;
        this.value = value;
    }
    
    /**
     * Representation of a property where the user can select from a list of choices.
     *  
     * @param name name of the property
     * @param type one of CustomPublisherProperty.UI_* constants (only UI_TEXTINPUT or UI_BOOLEAN makes sense in the current implementation)
     * @param value the current value of this property
     */
    public CustomPublisherProperty(final String name, final int type, final String value) {
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

    /** @return the name of this property */
    public String getName() { return name; }
    /** @return one of the CustomPublisherProperty.UI_* constants */
    public int getType() { return type; }
    /** @return a List of values this property can have or null if this does not apply to the type */
    public List<String> getOptions() { return options; }
    /** @return a List of user-friendly texts corresponding to the values this property can have or null if this does not apply to the type */
    public List<String> getOptionTexts() { return optionTexts; }
}
