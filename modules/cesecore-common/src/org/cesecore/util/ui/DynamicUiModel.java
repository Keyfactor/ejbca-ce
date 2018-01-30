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
import java.util.Map;

/**
 * Interface type for domain objects (or other objects) with dynamic UI model.
 * 
 * @version $Id: DynamicUiModel.java 26390 2017-11-04 15:20:58Z anjakobs $
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
    
//    /**
//     * Updates the value for a dynamic UI property and marks the UI model as updated.
//     * 
//     * @param name the name of the dynamic UI property.
//     * @param value the value.
//     */
//    void updateProperty(final String name, Serializable value);
//    
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
    
//    /**
//     * Denotes weather the PSM needs to be updated (i.e. reinitializes the UI components after enabling or disabling).
//     * @return true if the PSM needs to be recreated.
//     */
//    boolean isPsmRequiresUpdate();
//    
//    /**
//     * Denotes weather the PSM needs to be updated (i.e. reinitializes the UI components after enabling or disabling).
//     * @param state true if the PSM needs to be recreated.
//     */
//    void setPsmRequiresUpdate(boolean state);
}
