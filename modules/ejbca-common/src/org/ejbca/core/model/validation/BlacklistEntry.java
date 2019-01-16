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

package org.ejbca.core.model.validation;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

/**
 * Domain class representing a blacklist entry.
 *  
 *
 * @version $Id: PublicKeyBlacklistEntry.java 26283 2017-08-12 16:00:56Z anatom $
 */
public class BlacklistEntry implements Serializable, Cloneable {

    private static final long serialVersionUID = 1L;

    // Values used for lookup that are not stored in the data hash map.
    private int id;
    private String type;
    private String value;
    private String data;

    /**
     * Creates a new instance, must specify at least type.
     */
    public BlacklistEntry(String type) {
        this.type = type;
    }

    /**
     * Creates a new instance.
     */
    public BlacklistEntry(int id, String type, String value, String data) {
        this.id = id;
        this.type = type;
        this.value = value;
        this.data = data;
    }

    /**
     * Gets the blacklist id.
     * @return
     */
    public int getID() {
        return id;
    }

    /**
     * Sets the blacklist id.
     * @param id
     */
    public void setID(int id) {
        this.id = id;
    }   

    /**
     * Gets the blacklist specific type
     * @return type String, specified by specific blacklist type
     */
    public String getType() {
        return type;
    }

    /**
     * Gets the blacklist specific data.
     * @return a blacklist specified string
     */
    public String getData() {
        return data;
    }

    /**
     * Sets the blacklist specific data.
     * @param data a blacklist specified string.
     */
    public void setData(String data) {
        this.data = data;
    }
    
    /**
     * Gets the blacklisted value.
     * @return value
     */
    public String getValue() {
        return value;
    }

    /**
     * Sets the blacklisted value
     * @param value
     */
    public void setValue(String value) {
        this.value = value;
    }


    public Map<Object, Object> diff(BlacklistEntry newEntry) {
        final Map<Object, Object> result = new LinkedHashMap<>();
        if (!StringUtils.equals(this.getValue(), newEntry.getValue())) {
            result.put("changed:value", newEntry.getValue() == null ? "null" : newEntry.getValue());
        }
        if (!StringUtils.equals(this.getData(), newEntry.getData())) {
            result.put("changed:data", newEntry.getData() == null ? "null" : newEntry.getData());
        }
        return result;
    }

}
