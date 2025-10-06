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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public final class XmlUtil {

    public static String toXml(final Map<Object, Object> map) {
        if (map == null) {
            return null;
        }
        else {
            try {
                // We must base64 encode string for UTF safety
                final Base64PutHashMap base64PutHashMap = new Base64PutHashMap();
                base64PutHashMap.putAll(map);
                final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                final java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(outputStream);
                encoder.writeObject(base64PutHashMap);
                encoder.close();
                return outputStream.toString("UTF8");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<Object, Object> fromXml(final String xml) {
        if (xml == null) {
            return Map.of();
        }
        else {
            try (SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))) {
                final Map<?, ?> map = (Map<?, ?>)decoder.readObject();
                // Handle Base64 encoded string values
                final var base64GetHashMap = new Base64GetHashMap(map);
                return base64GetHashMap;
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    public static Map<String, Object> getDiff(Map<Object, Object> oldmap, Map<Object, Object> newmap) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Object key : oldmap.keySet()) {
            if (newmap.containsKey(key)) {
                // Check if the value is the same
                Object value = oldmap.get(key);
                if (value == null) {
                    if (newmap.get(key) != null) {
                        result.put("addedvalue:"+key, newmap.get(key));
                    }
                } else if (!value.equals(newmap.get(key))) {
                    Object val = newmap.get(key);
                    if (val == null) {
                        val = "";
                    }
                    result.put("changed:"+key, getVal(val));
                }
            } else {
                // Value removed
                Object val = oldmap.get(key);
                if (val == null) {
                    val = "";
                }
                result.put("removed:"+key, getVal(val));
            }
        }
        // look for added properties
        for (Object key : newmap.keySet()) {
            if (!oldmap.containsKey(key)) {
                Object val = newmap.get(key);
                if (val == null) {
                    val = "";
                }
                result.put("added:"+key, getVal(val));
            }
        }
        return result;
    }

    /** helper method to get nice output from types that do
     * not work nicely with Object.toString()
     */
    private static String getVal(Object o) {
        StringBuilder b = new StringBuilder();
        if (o instanceof String[]) {
            b.append('[');
            String[] arr = (String[]) o;
            for (String s: arr) {
                if (b.length() > 1) {
                    b.append(", ");
                }
                b.append(s);
            }
            b.append(']');
        } else {
            b.append(o);
        }
        return b.toString();
    }

}
