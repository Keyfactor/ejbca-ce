/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model;

import java.util.HashMap;



/**
 * UpgradeableDataHashMap is an class implementing the IUpgradeableData intended to be extended by
 * classes saving it's data to a database in BLOB/CLOB form.
 *
 * @version $Id$
 *
 * @see org.ejbca.core.model.IUpgradeableData
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
        data = new HashMap<Object, Object>();
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
        return data;
    }

    /**
     * @see IUpgradeableData#loadData(Object)
     */
    public void loadData(final Object data) {
    	this.data = (HashMap<Object, Object>) data;
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

    protected HashMap<Object, Object> data;
    private boolean upgraded = false;
	public static final String VERSION = "version";
}
