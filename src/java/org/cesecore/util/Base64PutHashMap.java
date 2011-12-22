/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.util;

import java.util.LinkedHashMap;
import java.util.Map;


/**
 * An implementation of HashMap that base64 encodes all String's that you 'put', it encodes them to form "B64:<base64 encoded string>". It only
 * encodes objects of type String.
 * 
 * Based on Base64PutHashMap.java 317 2011-02-23 16:26:16Z tomas from cesecore
 * 
 * TODO: Look over this object, see if it can be implemented with generics.
 * 
 * @version $Id$
 */
public class Base64PutHashMap extends LinkedHashMap<String, Object> {

    private static final long serialVersionUID = 785586648964618032L;

    public Base64PutHashMap() {
        super();
    }

    public Base64PutHashMap(Map<String, Object> m) {
        super(m);
    }

    public Object put(String key, Object value) {
        if (value == null) {
            return super.put(key, value);
        }
        if (value instanceof String) {
            String s = StringTools.putBase64String((String) value, true);
            return super.put(key, s);
        }
        return super.put(key, value);
    }

}
