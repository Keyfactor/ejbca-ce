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
package org.ejbca.util;

import java.io.Serializable;

/** 
 * Object holding a Key and a Value pair used, for example, to hold properties.
 */
public class KeyValuePair implements Serializable{

    /** Serial version UID, must be changed if class undergoes structural changes */
    private static final long serialVersionUID = 6515156937734311728L;
    
    /** A key, for example a property's key */
    private String key;
    /** A value, for example a property's value */
    private String value;

    
    public KeyValuePair() {
        this.key = null;
        this.value = null;
    }
    
    public KeyValuePair(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
