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

import com.keyfactor.util.StringTools;

/**
 * An implementation of HashMap that base64 encodes all String's that you 'put', if it's not asciiPrintable, where Base64 encoding is not needed. 
 * It encodes (non asciiPrintable) to form "B64:<base64 encoded string>". It only encodes objects of type String.
 */
public class Base64PutHashMap extends LinkedHashMap<Object, Object> {

    private static final long serialVersionUID = 785586648964618032L;

    public Base64PutHashMap() {
        super();
    }

    public Base64PutHashMap(Map<?, ?> m) {
        super(m);
    }

    @Override
    public Object put(final Object key, final Object value) {
        if (value == null) {
            return super.put(key, value);
        }
        if (value instanceof String) {
            String s = StringTools.putBase64String((String) value, true);
            return super.put(key, s);
        }
        return super.put(key, value);
    }

    @Override
    public void putAll(Map<? extends Object, ? extends Object> map) {
        // HashMap has an optimized putAll() method, which bypasses put()
        // So we need to override it with the basic version.
        for (final Map.Entry<? extends Object, ? extends Object> entry : map.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }
}
