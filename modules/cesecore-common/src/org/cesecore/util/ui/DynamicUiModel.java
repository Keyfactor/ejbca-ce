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

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * Base implementation for domain objects (or other objects) with dynamic UI properties.
 *
 * @version $Id$
 *
 */
public class DynamicUiModel {

    public static final String BASECLASS_PREFIX = "BASECLASS_";

    public static final String SUBCLASS_PREFIX = "SUBCLASS_";

    public static final String LIST_SEPARATOR = ";";
    
    /** Class logger. */
    private static final Logger log = Logger.getLogger(DynamicUiModel.class);

    /** Reference to data map. */
    private LinkedHashMap<Object, Object> data;

    /** List of dynamic UI properties. */
    private final LinkedHashMap<String, DynamicUiProperty<? extends Serializable>> properties = new LinkedHashMap<>();

    /** Property change support for dynamic UI components (MUST have same content as java.util.Map 'viewComponents'. */
    protected PropertyChangeSupport propertyChangeSupport;

    protected Map<String,List<DynamicUiComponent>> viewComponents;

    // True if the dynamic UI input components shall be disabled (i.e. view only).
    protected boolean disabled = false;

    /**
     * Default constructor, required for serialization.
     */
    public DynamicUiModel() {
        super();
    }

    /**
     * Constructor with reference to the entity backing map.
     * @param data the map.
     */
    public DynamicUiModel(final LinkedHashMap<Object, Object> data) {
        this(data, data);
    }

    /**
     * Constructor with reference to the entity backing map.
     * @param data the map.
     * @param filteredDataToLog data to debug log, with large values removed.
     */
    public DynamicUiModel(final LinkedHashMap<Object, Object> data, final LinkedHashMap<Object, Object> filteredDataToLog) {
        super();
        propertyChangeSupport = new PropertyChangeSupport(this);
        viewComponents = new HashMap<String,List<DynamicUiComponent>>();
        this.data = data;
        if (log.isDebugEnabled()) {
            log.debug("Create dynamic UI model with data: " + filteredDataToLog);
        }
    }

    /**
     * Adds a dynamic UI property to UI properties template.
     *
     * @param property the dynamic UI property to add.
     */
    public void add(DynamicUiProperty<? extends Serializable> property) {
        property.setDynamicUiModel(this);
        properties.put(property.getName(), property);
    }

    /**
     * Gets a copy of all dynamic UI properties from the UI properties template.
     *
     * @return the copy.
     */
    public Map<String, DynamicUiProperty<? extends Serializable>> getProperties() {
        return properties;
    }

    /**
     * Gets a dynamic UI property from the UI properties template.
     *
     * @param name the name of the dynamic UI property.
     * @return the dynamic property.
     */
    public DynamicUiProperty<? extends Serializable> getProperty(String name) {
        final DynamicUiProperty<? extends Serializable> property = properties.get(name);
//        property.setValueGeneric(getData(name, property.getDefaultValue()));
        return property;
    }

    /**
     * Sets the value for a dynamic UI property.
     *
     * @param name the name of the dynamic UI property.
     * @param value the value.
     */
    public void setProperty(String name, Serializable value) {
        if (log.isDebugEnabled()) {
            log.debug("Set domain object attribute by dynamic property " + name + " with value " + value);
        }
        putData(name, value);
    }

    /**
     * Gets the raw data map for the dynamic properties.
     * @return the raw data map.
     */
    public Map<String,Object> getRawData() {
        final LinkedHashMap<String,Object> result = new LinkedHashMap<String,Object>();
        for (Entry<String,DynamicUiProperty<?>> entry : properties.entrySet()) {
            if (entry.getValue().isTransientValue()) {
                continue;
            }
            if (entry.getValue().getHasMultipleValues()) {
                if (entry.getValue().isSaveListAsString()) {
                    result.put(entry.getKey(), StringUtils.join(entry.getValue().getValues(), LIST_SEPARATOR));
                } else {
                    result.put(entry.getKey(), entry.getValue().getValues());
                }
            } else {
                // BigInteger is written into XML object as String (XMLEncoder cannot write
                // data type classes without default constructor).
                if (BigInteger.class.equals(entry.getValue().getType()) && entry.getValue() != null && entry.getValue().getValue() != null) {
                    result.put(entry.getKey(), entry.getValue().getValue().toString());
                } else {
                    result.put(entry.getKey(), entry.getValue().getValue());
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Create dynamic UI properties raw data: " + result);
        }
        return result;
    }

    /**
     * Writes the properties to the data map (does conversions, i.e. in case of BigInteger etc.).
     * @param data the data map of the entity.
     */
    public void writeProperties(Map<Object, Object> data) {
        data.putAll(getRawData());
        if (log.isDebugEnabled()) {
            log.debug("Dynamic UI properties was written into data map: " + data);
        }
    }

    /** Store data in the underlying map. Encourages use of String valued keys. */
    private void putData(final String key, final Object value) {
        data.put(key, value);
    }

    /**
     * Adds a dynamic UI component for the property with the given name.
     * @param name the properties name.
     * @param component the dynamic UI component.
     */
    public void addDynamicUiComponent(final String name, final DynamicUiComponent component) {
        propertyChangeSupport.addPropertyChangeListener(name, (PropertyChangeListener) component);
        if (viewComponents.get(name) == null) {
            viewComponents.put(name, new ArrayList<DynamicUiComponent>());
        }
        viewComponents.get(name).add(component);
    }

    /**
     * Removes a dynamic UI component for the property with the given name.
     * @param name the properties name.
     * @param component the dynamic UI component.
     */
    public void removeDynamicUiComponent(final String name, final DynamicUiComponent component) {
        propertyChangeSupport.removePropertyChangeListener(name, (PropertyChangeListener) component);
        if (viewComponents.get(name) != null) {
            viewComponents.get(name).remove(component);
        }
    }

    /**
     * Gets a list of dynamic UI components for the property with the given name.
     * @param name the properties name.
     * @return the list of dynamic UI components for this property.
     */
    public List<DynamicUiComponent> getViewComponents(String name) {
        final List<DynamicUiComponent> result = new ArrayList<DynamicUiComponent>();
        if (viewComponents.get(name) != null) {
            result.addAll(viewComponents.get(name));
        }
        return result;
    }

    /**
     * Fires a property change event for the property with the given name.
     * @param name the properties name.
     * @param oldValue the old value.
     * @param newValue the new value.
     */
    public void firePropertyChange(final String name, final Object oldValue, final Object newValue) {
        if (log.isTraceEnabled()) {
            log.trace("Fire dynamic UI model property change event for " + name + " with old value " + oldValue + ", new value " + newValue);
        }
        propertyChangeSupport.firePropertyChange(name, oldValue, newValue);
        final DynamicUiProperty<?> property = getProperty(name);
        if (property != null) {
            property.updateViewComponents();
        }
    }

    /**
     * Fire a property change event for the properties.
     * @param oldValues the map of old values.
     * @param newValues the map of new values.
     */
    @SuppressWarnings("unchecked")
    public void firePropertyChange(final Map<Object, Object> oldValues, final Map<Object, Object> newValues) {
        if (log.isTraceEnabled()) {
            log.trace("Fire dynamic UI model property change event with old values " + oldValues + ", new values " + newValues);
        }
        if (propertyChangeSupport != null) {
            DynamicUiProperty<?> property;
            for (Object key : newValues.keySet()) {
                property = getProperty((String) key);
                if (property != null) {
                    // Update dynamic UI model (if not done already).
                    if (property.getHasMultipleValues()) {
                        property.setValuesGeneric((List<Serializable>) newValues.get(key));
                    } else {
                        property.setValueGeneric((Serializable) newValues.get(key));
                    }
                    // Update UIs.
                    firePropertyChange((String) key, oldValues.get(key), newValues.get(key));
                }
            }
        }
    }

    /**
     * Gets if the dynamic UI input components shall be disabled.
     * @return true if the dynamic UI input components shall be disabled (i.e. view only).
     */
    public boolean isDisabled() {
        return disabled;
    }

    /**
     * Sets if the dynamic UI input components shall be disabled.
     * @param disabled if the dynamic UI input components shall be disabled (i.e. view only).
     */
    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }
}
