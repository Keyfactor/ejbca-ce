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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Utility functions to work with maps.
 * 
 * @version $Id$
 */
public final class MapTools {
    
    /** Utility class, cannot be instantiated */
    private MapTools() { }
    
    /**
     * Adds an item to a map, and returns it. Useful for initialization:
     * <code>
     * doWorkWithMapExample(addToMap(new HashMap<Integer,String>(), 0, "none"));
     * </code>
     * 
     * <p>Unlike the <code>new HashMap<>() {{ put(x,y); }}</code> pattern, this does not create a new class (which can create problems with de-serialization)
     * 
     * @param map Map to use.
     * @param key1 First key.
     * @param value1 Value of first key.
     * @return Returns the map.
     * @see #addToMap(Map, Object, Object, Object, Object)
     * @see #addToMap(Map, Object, Object, Object, Object, Object, Object)
     */
    public static <K,V> Map<K,V> addToMap(final Map<K,V> map, final K key1, final V value1) {
        map.put(key1, value1);
        return map;
    }
    
    /**
     * Adds two items to a map, and returns it. Useful for initialization. See {@link #addToMap(Map, Object, Object)}.
     * @see #addToMap(Map, Object, Object)
     * @see #addToMap(Map, Object, Object, Object, Object, Object, Object)
     */
    public static <K,V> Map<K,V> addToMap(final Map<K,V> map, final K key1, final V value1, final K key2, final V value2) {
        map.put(key1, value1);
        map.put(key2, value2);
        return map;
    }
    
    /**
     * Adds three items to a map, and returns it. Useful for initialization. See {@link #addToMap(Map, Object, Object)}.
     * @see #addToMap(Map, Object, Object)
     * @see #addToMap(Map, Object, Object, Object, Object)
     */
    public static <K,V> Map<K,V> addToMap(final Map<K,V> map, final K key1, final V value1, final K key2, final V value2, final K key3, final V value3) {
        map.put(key1, value1);
        map.put(key2, value2);
        map.put(key3, value3);
        return map;
    }
    
    /**
     * Creates an unmodifiable map with two items. The returned map is backed by a LinkedHashMap, so it preserves order. Useful for initialization:
     * <code>
     * doWorkWithMapExample(unmodifiableMap(0, "none"));
     * </code>
     * 
     * <p>Unlike the <code>new HashMap<>() {{ put(x,y); }}</code> pattern, this does not create a new class (which can create problems with de-serialization)
     * 
     * @param key1 First key.
     * @param value1 Value of first key.
     * @return Returns the map.
     * @see #unmodifiableMap(Object, Object, Object, Object)
     * @see #unmodifiableMap(Object, Object, Object, Object, Object, Object)
     */
    public static <K,V> Map<K,V> unmodifiableMap(final K key1, final V value1) {
        return Collections.unmodifiableMap(addToMap(new LinkedHashMap<K,V>(), key1, value1));
    }
    
    
    /**
     * Creates an unmodifiable map with two items. The returned map is backed by a LinkedHashMap, so it preserves order.
     * Useful for initialization. See {@link #unmodifiableMap(Object, Object)}.
     * @see #unmodifiableMap(Object, Object)
     * @see #unmodifiableMap(Object, Object, Object, Object, Object, Object)
     */
    public static <K,V> Map<K,V> unmodifiableMap(final K key1, final V value1, final K key2, final V value2) {
        return Collections.unmodifiableMap(addToMap(new LinkedHashMap<K,V>(), key1, value1, key2, value2));
    }
    
    /**
     * Creates an unmodifiable map with two items. The returned map is backed by a LinkedHashMap, so it preserves order.
     * Useful for initialization. See {@link #unmodifiableMap(Object, Object)}.
     * @see #unmodifiableMap(Object, Object)
     * @see #unmodifiableMap(Object, Object, Object, Object)
     */
    public static <K,V> Map<K,V> unmodifiableMap(final K key1, final V value1, final K key2, final V value2, final K key3, final V value3) {
        return Collections.unmodifiableMap(addToMap(new LinkedHashMap<K,V>(), key1, value1, key2, value2, key3, value3));
    }

    /**
     * Returns a human readable string representation for a map, based on toString() from the keys and values. 
     * @param map Map of any type. May contain keys and values that are null.
     * @return The string, for example <code>{'key 1': 'value 1', 'key 2': null}</code>
     */
    public static String toString(final Map<?, ?> map) {
        final StringBuilder sb = new StringBuilder();
        boolean first = true;
        sb.append('{');
        for (final Entry<?,?> entry : map.entrySet()) {
            if (!first) sb.append(", ");
            appendToStringOrNull(sb, entry.getKey());
            sb.append(": ");
            appendToStringOrNull(sb, entry.getValue());
        }
        sb.append('}');
        return sb.toString();
    }

    private static void appendToStringOrNull(final StringBuilder sb, final Object obj) {
        if (obj == null) {
            sb.append("null");
        } else {
            sb.append('\'');
            sb.append(obj);
            sb.append('\'');
        }
    }

    /**
     * Sorts a LinkedHashMap by values, using the given comparator
     * @param map LinkedHashMap to sort by values.
     * @param comparator Comparator to compare values using.
     */
    public static <K,V> void sortLinkedHashMap(final LinkedHashMap<K,V> map, final Comparator<V> comparator) {
        final List<Entry<K,V>> entries = new ArrayList<>(map.entrySet());
        Collections.sort(entries, new Comparator<Entry<K,V>>() {
            @Override
            public int compare(final Entry<K, V> o1, final Entry<K, V> o2) {
                return comparator.compare(o1.getValue(), o2.getValue());
            }
        });
        map.clear();
        for (final Entry<K,V> entry : entries) {
            map.put(entry.getKey(), entry.getValue());
        }
    }

}
