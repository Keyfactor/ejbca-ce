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
 
package se.anatom.ejbca.util;

import java.util.HashMap;


/**
 * UpgradeableDataHashMap is an class implementing the IUpgradeableData intended to be extended by
 * classes saving it's data to a database in BLOB form.
 *
 * @version $Id: UpgradeableDataHashMap.java,v 1.6 2004-04-16 07:38:59 anatom Exp $
 *
 * @see se.anatom.ejbca.util.IUpgradeableData
 */
public abstract class UpgradeableDataHashMap implements IUpgradeableData, java.io.Serializable {
    /**
     * Creates a new UpgradeableDataHashMap object.
     */
    public UpgradeableDataHashMap() {
        data = new HashMap();
        data.put(VERSION, new Float(getLatestVersion()));
    }

    /**
     * Should return a constant containing the latest available version of the class.
     *
     * @return DOCUMENT ME!
     */
    public abstract float getLatestVersion();

    /**
     * Function returning the current version of the class data.
     *
     * @return DOCUMENT ME!
     */
    public float getVersion() {
        return ((Float) data.get(VERSION)).floatValue();
    }

    /**
     * Function sending the data to be saved to the database.
     *
     * @return DOCUMENT ME!
     */
    public Object saveData() {
        return (Object) data;
    }

    /**
     * Function loading saved data into to data structure.
     *
     * @param data DOCUMENT ME!
     */
    public void loadData(Object data) {
        this.data = (HashMap) data;

        if (getLatestVersion() > getVersion()) {
            upgrade();
        }
    }

    /**
     * Function that should handle the update if of the data in the class so it's up to date with
     * the latest version. An update is only done when needed.
     */
    public abstract void upgrade();

    protected HashMap data;
    protected static final String VERSION = "version";
}
