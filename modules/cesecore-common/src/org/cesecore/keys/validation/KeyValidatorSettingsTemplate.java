/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.util.IndexEnum;

/**
 * An enum domain class representing all key validator base parameter options.
 *
 * @version $Id$
 */
public enum KeyValidatorSettingsTemplate implements IndexEnum {

    // @formatter:off
    USE_CERTIFICATE_PROFILE_SETTINGS(0, "VALIDATORSETTINGSTEMPLATE_USE_CP_SETTINGS"), 
    USE_CAB_FORUM_SETTINGS(1, "VALIDATORSETTINGSTEMPLATE_USE_CAB_FORUM_SETTINGS"), 
    USE_CUSTOM_SETTINGS(2, "VALIDATORSETTINGSTEMPLATE_USE_CUSTOM_SETTINGS");
    // @formatter:on

    /** The unique option index. */
    private int option;

    /** The resource key or label. */
    private String label;

    /**
     * Creates a new instance.
     * 
     * @param option option index
     * @param label resource key or label.
     */
    private KeyValidatorSettingsTemplate(final int option, final String label) {
        this.option = option;
        this.label = label;
    }

    /**
     * Gets the option index.
     */
    public int getOption() {
        return option;
    }

    /**
     * Gets the resource key or label.
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets an Integer list instance containing all options.
     */
    public static final List<Integer> types() {
        final List<Integer> result = new ArrayList<>();
        for (KeyValidatorSettingsTemplate option : values()) {
            result.add(option.getOption());
        }
        return result;
    }
    
    /**
     * Gets a String list instance containing all I18N label keys.
     */
    public static final Map<Integer,String> map() {
        final Map<Integer,String> result = new LinkedHashMap<>();
        for (KeyValidatorSettingsTemplate option : values()) {
            result.put(option.getOption(), option.getLabel());
        }
        return result;
    }

    /**
     * Gets the KeyValidatorBaseParameterOptions object with the option optionIndex
     * @param optionIndex the options index
     * @return the option.
     */
    public static final KeyValidatorSettingsTemplate optionOf(final int optionIndex) {
        KeyValidatorSettingsTemplate result = null;
        for (KeyValidatorSettingsTemplate option : values()) {
            if (option.getOption() == optionIndex) {
                result = option;
            }
        }
        return result;
    }

    @Override
    public int getIndex() {
        return getOption();
    }
    
    /**
     * Retrieve an template settings from its index. Currently used in configdump.
     * @param index the index of the template settings
     * @return the corresponding template settings enum or null if not found
     */
    public static KeyValidatorSettingsTemplate fromIndex(final int index) {
        return optionOf(index);
    }
}
