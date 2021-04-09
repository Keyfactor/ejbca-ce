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
package org.ejbca.configdump;

import java.io.Serializable;

import org.apache.commons.lang3.StringUtils;
import org.cesecore.util.ui.DynamicUiPropertyValidator;

/**
 * Config dump property of a given type.
 * 
 * The lower camel case key is mapped to a space separated capitalized 
 * words string. I.e. the key 'typeIdentifier' is mapped to 'Type Identifier' 
 * in the YAML file.
 * 
 * @version $Id$
 */
public class ConfigdumpProperty<T extends Serializable> {

    /** Data type. */
    private Class<T> type;
    
    /** Key of EJBCA objects backing data map. */
    private String key;
    
    /** Value of EJBCA objects backing data map. */
    private T value;
    
    /** Property validator to validate import data. */
    private DynamicUiPropertyValidator<T> validator;

    /**
     * Creates a config dump property.
     * 
     * @param type the data type.
     * @param key the lower camel case key.
     * @param value the data value.
     */
    public ConfigdumpProperty(Class<T> type, String key, T value) {
        super();
        this.type = type;
        this.key = key;
        this.value = value;
    }
    
    /**
     * Creates a config dump property.
     * 
     * @param type the data type.
     * @param key the lower camel case key.
     * @param value the data value.
     * @param validator the property validator.
     */
    public ConfigdumpProperty(Class<T> type, String key, T value, DynamicUiPropertyValidator<T> validator) {
        this(type, key, value);
        this.validator = validator;
    }

    /**
     * Returns the data type of the property.
     * 
     * @return the data type.
     */
    public Class<T> getType() {
        return type;
    }

    /**
     * Returns the lower camel case key string.
     * 
     * @return the key string.
     */
    public String getKey() {
        return key;
    }

    /**
     * Returns the YAML label (use as key as well) as space separated capitalized words string.
     * 
     * @return the label string.
     */
    public String getLabel() { 
        return keyToLabel(key);
    }

    /**
     * Return the value.
     * 
     * @return the value. 
     */
    public T getValue() {
        return value;
    }
    
    /**
     * Returns the property validator.
     * 
     * @return the validator or null.
     */
    public DynamicUiPropertyValidator<T> getValidator() {
        return validator;
    }

    /**
     * Returns a space separated capitalized words string by the given lower camel case string.
     * 
     * @param key the lower camel case string (may be a single word).
     * @return the string.
     */
    public static final String keyToLabel(final String key) {
        final StringBuffer label = new StringBuffer();   
        for (String w : key.split("(?<!(^|[a-z]))(?=[A-Z])|(?<!^)(?=[A-Z][a-z])")) {
            if (label.length() > 0) {
                label.append(" ");
            }
            label.append(w);
        }
        return StringUtils.capitalize(label.toString());
    }
    
    /**
     * Returns a lower camel case string by the given space separated capitalized words string.
     *  
     * @param label the space separated capitalized words string (may be a single word). 
     * @return the string. 
     */
    public static final String labelToKey(final String label) {
        StringBuffer key = new StringBuffer();   
        for (String w : label.split("(?<!(^|[A-Z]))(?=[A-Z])|(?<!^)(?=[A-Z][a-z])")) {
            if (key.length() > 0) {
                key = new StringBuffer(key.substring(0, key.length()-1));
            }
            key.append(w);
        }    
        return StringUtils.uncapitalize(key.toString());
    }
    
    public static final ConfigdumpProperty<Boolean> booleanInstance(final String key, final boolean value) {
        return new ConfigdumpProperty<Boolean>(Boolean.class, key, value);
    }
    
    public static final ConfigdumpProperty<String> stringInstance(final String key, final String value) {
        return new ConfigdumpProperty<String>(String.class, key, value);
    }
    
    public static final ConfigdumpProperty<String> stringInstance(final String key, final String value, 
            final DynamicUiPropertyValidator<String> validator) {
        return new ConfigdumpProperty<String>(String.class, key, value, validator);
    }
    
    public static final ConfigdumpProperty<Float> floatInstance(final String key, final float value) {
        return new ConfigdumpProperty<Float>(Float.class, key, value);
    }
}
