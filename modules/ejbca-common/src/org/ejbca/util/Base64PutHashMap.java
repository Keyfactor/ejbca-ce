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

import java.util.HashMap;
import java.util.Map;

import org.cesecore.util.StringTools;

/** Only used for backwards compatibility with earlier versions of EJBCA
 * @see org.cesecore.util.Base64PutHashMap
 * @deprecated
 */
@Deprecated
public class Base64PutHashMap extends HashMap<Object, Object> {
    private static final long serialVersionUID = 4700506858751520533L;

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
            String s = StringTools.putBase64String((String) value);
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
