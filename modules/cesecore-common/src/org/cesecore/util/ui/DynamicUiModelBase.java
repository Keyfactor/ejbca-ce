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
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * Base implementation for domain objects (or other objects) with dynamic UI properties.
 * 
 * @version $Id: DynamicUiModelBase.java 26390 2017-11-04 15:20:58Z anjakobs $
 *
 */
public class DynamicUiModelBase implements DynamicUiModel {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(DynamicUiModelBase.class);

    /** Reference to data map. */
    private LinkedHashMap<Object, Object> data;

    /** List of dynamic UI properties. */
    private final LinkedHashMap<String, DynamicUiProperty<? extends Serializable>> properties = new LinkedHashMap<>();
    
    private boolean updated = false;

//    private boolean psmRequiresUpdate = true;
    
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
        this.data = data;
        if (log.isDebugEnabled()) {
            log.debug("Create dynmic UI model with data: " + data);
        }
    }

    @Override
    public void add(DynamicUiProperty<? extends Serializable> property) {
        property.setDynamicUiProperties(this);
        properties.put(property.getName(), property);
    }

    @Override
    public Map<String, DynamicUiProperty<? extends Serializable>> getProperties() {
        return properties;
    }

    @Override
    public DynamicUiProperty<? extends Serializable> getProperty(String name) {
        final DynamicUiProperty<? extends Serializable> property = properties.get(name);
        property.setValueGeneric(getData(name, property.getDefaultValue()));
        return property;
    }

    @Override
    public void setProperty(String name, Serializable value) {
        if (log.isDebugEnabled()) {
            log.debug("Set domain object attribute by dynamic property " + name + " with value " + value);
        }
        putData(name, value);
    }
    
//    @Override
//    public void updateProperty(String name, Serializable value) {
//        if (log.isDebugEnabled()) {
//            log.debug("Update domain object attribute by dynamic property " + name + " with value " + value);
//        }
//        putData(name, value);
//        setUpdated(true);
//    }
    
    /**
     * Return true if the dynamic UI model was updated and the PSM needs to be re-built.
     * @return if the PSM needs to be re-built.
     */
    public boolean isUpdated() {
        return updated;
    }

    /**
     * Mark the dynamic UI model as updated.
     * @param updated true if the PSM has to be re-built.
     */
    public void setUpdated(final boolean updated) {
        this.updated = updated;
    }
    
//    @Override
//    public boolean isPsmRequiresUpdate() {
//        return psmRequiresUpdate;
//    }
//
//    @Override
//    public void setPsmRequiresUpdate(final boolean psmRequiresUpdate) {
//        this.psmRequiresUpdate = psmRequiresUpdate;
//    }

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

    /** @return data from the underlying map. Encourages use of string valued keys. */
    @SuppressWarnings("unchecked")
    private <T> T getData(final String key, final T defaultValue) {
        final T result = (T) data.get(key);
        return result == null ? defaultValue : result;
    }

    /** Store data in the underlying map. Encourages use of String valued keys. */
    private void putData(final String key, final Object value) {
        data.put(key, value);
    }
}
