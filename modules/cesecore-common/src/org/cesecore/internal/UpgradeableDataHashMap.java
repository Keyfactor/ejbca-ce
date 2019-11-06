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

package org.cesecore.internal;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.cesecore.util.Base64GetHashMap;



/**
 * UpgradeableDataHashMap is an class implementing the IUpgradeableData intended to be extended by
 * classes saving it's data to a database in BLOB/CLOB form.
 *
 * @version $Id$
 *
 * @see org.cesecore.internal.IUpgradeableData
 */
public abstract class UpgradeableDataHashMap implements IUpgradeableData, Serializable {
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
	private static final long serialVersionUID = -1766329888474901945L;

    // Use LinkedHashMap because we want to have consistent serializing of the hashmap in order to be able to sign/verify data
    protected LinkedHashMap<Object, Object> data;
    private boolean upgraded = false;
    public static final String VERSION = "version";

	/**
     * Creates a new UpgradeableDataHashMap object.
     */
    public UpgradeableDataHashMap() {
        data = new LinkedHashMap<>();
        data.put(VERSION, getLatestVersion());
    }

    /**
     * @see IUpgradeableData#getLatestVersion()
     */
    @Override
    public abstract float getLatestVersion();

    /**
     * @see IUpgradeableData#getVersion()
     */
    @Override
    public float getVersion() {
        return (Float) data.get(VERSION);
    }

    /**
     * @see IUpgradeableData#saveData()
     */
    @Override
    public Object saveData() {
        return data.clone();
    }

    public LinkedHashMap<Object, Object> getRawData() {
        return data;
    }

    /**
     * @see IUpgradeableData#loadData(Object)
     */
    @Override
    @SuppressWarnings("unchecked")
    public void loadData(final Object savedData) {
    	// By creating a new LinkedHashMap (Base64GetHashMap) here we slip through a possible upgrade issue when upgrading
    	// from older implementation that used a plain HashMap instead.
    	// Both newer and older versions can be casted to HashMap.
    	data = new Base64GetHashMap((HashMap<?, ?>)savedData);
    	if(Float.compare(getLatestVersion(), getVersion()) > 0) {
    		upgrade();
    		upgraded = true;
    	}
    }

    /** So you can poll to see if the data has been upgraded
     *
     * @return true if data has been upgraded, false otherwise
     */
    public boolean isUpgraded() {
		return upgraded;
	}

    /**
     * Function that should handle the update if of the data in the class so it's up to date with
     * the latest version. An update is only done when needed.
     */
    @Override
    public abstract void upgrade();

    /**
     * @see IUpgradeableData#diff(UpgradeableDataHashMap)
     */
    @Override
    public Map<Object, Object> diff(UpgradeableDataHashMap newobj) {
    	@SuppressWarnings("unchecked")
        Map<Object, Object> newmap = (Map<Object, Object>)newobj.saveData();
    	return diffMaps(data, newmap);
    }

    /** Create a Map with the differences between the two input objects.
     * Puts the result in a new Map with keys:
     * <pre>
     * changed:key, changedvalue
     * remove:key, removedvalue
     * added:key, addedvalue
     * </pre>
     *
	 * @param oldmap
	 * @param newmap
	 * @return Map<Object, Object> with difference
	 */
	public static Map<Object, Object> diffMaps(Map<Object, Object> oldmap, Map<Object, Object> newmap) {
		Map<Object, Object> result = new LinkedHashMap<>();
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

	// Helper methods for interacting with the stored data

    /**
     * Retrieve a boolean value from the data map in a safe manner.
     * @param key the key for the value to retrieve
     * @param defaultValue the default value to return if the value with the specified key does
     *                     not exist in the map or cannot be cast to a boolean
     * @return the value mapped to the key specified as first parameter or the default value
     *         specified as second parameter if retrieval failed
     */
    protected boolean getBoolean(final String key, final boolean defaultValue) {
        final Object object = data.get(key);
        if (object == null || !(object instanceof Boolean)) {
            return defaultValue;
        }
        return (Boolean) object;
    }

    /**
     * Retrieve a non-null string value from the data map in a safe manner.
     * @param key the key for the value to retrieve
     * @param defaultValue the default value to return if the value with the specified key does
     *                     not exist in the map or cannot be cast to a string
     * @return the value mapped to the key specified as first parameter or the default value
     *         specified as second parameter if retrieval failed
     */
    protected String getString(final String key, final String defaultValue) {
        final Object object = data.get(key);
        if (object == null || !(object instanceof String)) {
            return defaultValue;
        }
        return (String) object;
    }

    /** Set the value for the specified key as a primitive (never null) boolean */
    protected void putBoolean(final String key, final boolean value) {
        data.put(key, Boolean.valueOf(value));
    }

    /**
     * @return a deep copy of this hashmap's data object, for cloning purposes.
     */
    protected LinkedHashMap<Object, Object> getClonedData() {
        // We need to make a deep copy of the hashmap here
        LinkedHashMap<Object, Object> clonedData = new LinkedHashMap<>(data.size());
        for (final Entry<Object,Object> entry : data.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof ArrayList<?>) {
                        // We need to make a clone of this object, but the stored immutables can still be referenced
                        value = ((ArrayList<?>)value).clone();
                }
                clonedData.put(entry.getKey(), value);
        }
        return clonedData;
    }


}
