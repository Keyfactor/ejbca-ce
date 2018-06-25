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
public class DynamicUiModelBase implements DynamicUiModel {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(DynamicUiModelBase.class);

    /** Reference to data map. */
    private LinkedHashMap<Object, Object> data;

    /** List of dynamic UI properties. */
    private final LinkedHashMap<String, DynamicUiProperty<? extends Serializable>> properties = new LinkedHashMap<>();

    /** Map of help texts **/
    private final Map<DynamicUiProperty<? extends Serializable>, String> helpTexts = new LinkedHashMap<DynamicUiProperty<? extends Serializable>, String>();

    /** Property change support for dynamic UI components (MUST have same content as java.util.Map 'viewComponents'. */
    protected PropertyChangeSupport propertyChangeSupport;

    protected Map<String,List<DynamicUiComponent>> viewComponents;

    // True if the dynamic UI input components shall be disabled (i.e. view only).
    protected boolean disabled = false;

    /**
     * Default constructor, required for serialization.
     */
    public DynamicUiModelBase() {
        super();
    }

    /**
     * Constructor with reference to the entity backing map.
     * @param data the map.
     */
    public DynamicUiModelBase(final LinkedHashMap<Object, Object> data) {
        super();
        propertyChangeSupport = new PropertyChangeSupport(this);
        viewComponents = new HashMap<String,List<DynamicUiComponent>>();
        this.data = data;
        if (log.isDebugEnabled()) {
            log.debug("Create dynmic UI model with data: " + data);
        }
    }

    @Override
    public void add(DynamicUiProperty<? extends Serializable> property) {
        property.setDynamicUiModel(this);
        properties.put(property.getName(), property);
    }

    @Override
    public Map<String, DynamicUiProperty<? extends Serializable>> getProperties() {
        return properties;
    }

    @Override
    public DynamicUiProperty<? extends Serializable> getProperty(String name) {
        final DynamicUiProperty<? extends Serializable> property = properties.get(name);
//        property.setValueGeneric(getData(name, property.getDefaultValue()));
        return property;
    }

    @Override
    public void setProperty(String name, Serializable value) {
        if (log.isDebugEnabled()) {
            log.debug("Set domain object attribute by dynamic property " + name + " with value " + value);
        }
        putData(name, value);
    }

    @Override
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
                // BigItnteger is written into XML object as String (XMLEncoder cannot write
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

    @Override
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

    @Override
    public void addDynamicUiComponent(final String name, final DynamicUiComponent component) {
        propertyChangeSupport.addPropertyChangeListener(name, (PropertyChangeListener) component);
        if (viewComponents.get(name) == null) {
            viewComponents.put(name, new ArrayList<DynamicUiComponent>());
        }
        viewComponents.get(name).add(component);
    }

    @Override
    public void removeDynamicUiComponent(final String name, final DynamicUiComponent component) {
        propertyChangeSupport.removePropertyChangeListener(name, (PropertyChangeListener) component);
        if (viewComponents.get(name) != null) {
            viewComponents.get(name).remove(component);
        }
    }

    @Override
    public List<DynamicUiComponent> getViewComponents(String name) {
        final List<DynamicUiComponent> result = new ArrayList<DynamicUiComponent>();
        if (viewComponents.get(name) != null) {
            result.addAll(viewComponents.get(name));
        }
        return result;
    }

    @Override
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

    @Override
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

    @Override
    public boolean isDisabled() {
        return disabled;
    }

    @Override
    public void setDisabled(boolean disabled) {
        this.disabled = disabled;
    }
}
