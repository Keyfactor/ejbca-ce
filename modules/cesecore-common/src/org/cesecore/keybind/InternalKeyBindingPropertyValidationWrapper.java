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
package org.cesecore.keybind;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * This class wraps the result of an internal key binding validation. It contains a defensive copy of the properties map
 * allowing values entered as strings to be recast as their proper values, and also contains lists of invalid values for
 * diagnostic purposes. 
 * 
 * @version $Id$
 *
 */
public class InternalKeyBindingPropertyValidationWrapper {

    private Map<String, Class<?>> invalidValues = new HashMap<String, Class<?>>();
    private List<String> unknownProperties = new ArrayList<String>();
    private Map<String, Serializable> propertiesCopy = new LinkedHashMap<String, Serializable>();

    public boolean arePropertiesValid() {
        return invalidValues.isEmpty() && unknownProperties.isEmpty();
    }

    public Map<String, Class<?>> getInvalidValues() {
        return invalidValues;
    }

    public List<String> getUnknownProperties() {
        return unknownProperties;
    }

    public Map<String, Serializable> getPropertiesCopy() {
        return propertiesCopy;
    }

    public void addInvalidValue(String value, Class<?> expected) {
        invalidValues.put(value, expected);
    }

    public void addUnknownProperty(String value) {
        unknownProperties.add(value);
    }

    public void addProperty(String key, Serializable value) {
        propertiesCopy.put(key, value);
    }

}
