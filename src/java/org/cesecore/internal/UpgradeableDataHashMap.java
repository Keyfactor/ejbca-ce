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

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.cesecore.util.Base64GetHashMap;



/**
 * UpgradeableDataHashMap is an class implementing the IUpgradeableData intended to be extended by
 * classes saving it's data to a database in BLOB/CLOB form.
 *
 * Based on EJBCA version: UpgradeableDataHashMap.java 11075 2011-01-07 07:40:42Z anatom
 * 
 * @version $Id: UpgradeableDataHashMap.java 1001 2011-08-18 11:02:01Z tomas $
 *
 * @see org.cesecore.internal.IUpgradeableData
 */
public abstract class UpgradeableDataHashMap implements IUpgradeableData, java.io.Serializable {
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
	
	/**
     * Creates a new UpgradeableDataHashMap object.
     */
    public UpgradeableDataHashMap() {
        data = new LinkedHashMap<Object, Object>();
        data.put(VERSION, new Float(getLatestVersion()));
    }

    /**
     * @see IUpgradeableData#getLatestVersion()
     */
    public abstract float getLatestVersion();

    /**
     * @see IUpgradeableData#getVersion()
     */
    public float getVersion() {
        return ((Float) data.get(VERSION)).floatValue();
    }

    /**
     * @see IUpgradeableData#saveData()
     */
    public Object saveData() {
        return data.clone();
    }

    /**
     * @see IUpgradeableData#loadData(Object)
     */
    @SuppressWarnings("unchecked")
    public void loadData(final Object data) {
    	// By creating a new LinkedHashMap (Base64GetHashMap) here we slip through a possible upgrade issue when upgrading
    	// from older implementation that used a plain HashMap instead. 
    	// Both newer and older versions can be casted to HashMap. 
    	this.data = new Base64GetHashMap((HashMap)data);
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
    public abstract void upgrade();

    /** Create a Map with the differences between the current object and the parameter object.
     * Puts the result in a new Map with keys:
     * <pre>
     * changed:key, changedvalue
     * remove:key, removedvalue
     * added:key, addedvalue
     * </pre>
     * 
     * @param newobj The "changed" object for which we want to get the changes compared to this object
     * @return Map object with difference as described above
     */
    public Map<Object, Object> diff(UpgradeableDataHashMap newobj) {
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
		Map<Object, Object> result = new LinkedHashMap<Object, Object>();
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
					result.put("changed:"+key, val);
				}
			} else {
				// Value removed
				Object val = oldmap.get(key);
				if (val == null) {
					val = ""; 
				}
				result.put("removed:"+key, val);
			}
		}
    	// look for added properties
    	for (Object key : newmap.keySet()) {
    		if (!oldmap.containsKey(key)) {
				Object val = newmap.get(key);
				if (val == null) {
					val = ""; 
				}
				result.put("added:"+key, val);    			
    		}
    	}
    	return result;
	}
    
    // Use LinkedHashMap because we want to have consistent serializing of the hashmap in order to be able to sign/verify data
    protected LinkedHashMap<Object, Object> data;
    private boolean upgraded = false;
	public static final String VERSION = "version";
}
