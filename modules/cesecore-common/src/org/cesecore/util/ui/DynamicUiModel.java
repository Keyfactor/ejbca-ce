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
package org.cesecore.util.ui;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

/**
 * Interface type for domain objects (or other objects) with dynamic UI model.
 * 
 * @version $Id$
 *
 */
public interface DynamicUiModel {

    public static final String BASECLASS_PREFIX = "BASECLASS_";
    
    public static final String SUBCLASS_PREFIX = "SUBCLASS_";
    
    public static final String LIST_SEPARATOR = ";";
    
    /**
     * Adds a dynamic UI property to UI properties template.
     * 
     * @param property the dynamic UI property to add.
     */
    void add(DynamicUiProperty<? extends Serializable> property);

    /**
     * Gets a copy of all dynamic UI properties from the UI properties template.
     * 
     * @return the copy.
     */
    Map<String, DynamicUiProperty<? extends Serializable>> getProperties();

    /**
     * Gets a dynamic UI property from the UI properties template.
     * 
     * @param name the name of the dynamic UI property.
     * @return the dynamic property.
     */
    DynamicUiProperty<? extends Serializable> getProperty(final String name);

    /**
     * Sets the value for a dynamic UI property.
     * 
     * @param name the name of the dynamic UI property.
     * @param value the value.
     */
    void setProperty(final String name, Serializable value);
    
    /**
     * Gets the raw data map for the dynamic properties.
     * @return the raw data map.
     */
    Map<String,Object> getRawData();
    
    /**
     * Writes the properties to the data map (does conversions, i.e. in case of BigInteger etc.).
     * @param data the data map of the entity.
     */
    void writeProperties(Map<Object,Object> data);
    
    /**
     * Adds a dynamic UI component for the property with the given name.
     * @param name the properties name.
     * @param component the dynamic UI component.
     */
    void addDynamicUiComponent(final String name, final DynamicUiComponent component);
    
    /**
     * Removes a dynamic UI component for the property with the given name.
     * @param name the properties name.
     * @param component the dynamic UI component.
     */
    void removeDynamicUiComponent(final String name, final DynamicUiComponent component);
    
    /**
     * Gets a list of dynamic UI components for the property with the given name.
     * @param name the properties name.
     * @return the list of dynamic UI components for this property.
     */
    List<DynamicUiComponent> getViewComponents(final String name);
    
    /**
     * Fires a property change event for the property with the given name.
     * @param name the properties name.
     * @param oldValue the old value.
     * @param newValue the new value.
     */
    void firePropertyChange(final String name, final Object oldValue, final Object newValue);
    
    /**
     * Fire a property change event for the properties.
     * @param oldValues the map of old values.
     * @param newValues the map of new values.
     */
    void firePropertyChange(final Map<Object, Object> oldValues, final Map<Object, Object> newValues);
}
