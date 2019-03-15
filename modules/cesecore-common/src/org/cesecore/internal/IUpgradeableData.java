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

import java.util.Map;

/**
 * IUpgradableData is an interface intended to be used by classed saved to database as BLOB. Every
 * such class should put all it's data in one of the Collection data structures and it will only
 * be the collection saved to the database. This is to avoid serialization problems when upgrading
 * the class.
 *
 * @version $Id$
 */
public interface IUpgradeableData {
    /**
     * Should return a constant containing the latest available version of the class.
     *
     * @return float version, for example 11 or 11.1
     */
    float getLatestVersion();

    /**
     * Function returning the current version of the class data.
     *
     * @return float version, for example 11 or 11.1
     */
    float getVersion();

    /**
     * Function sending the data to be saved to the database.
     *
     * @return Object to be stored in database, i.e. a HashMap for UpgradeableDataHashMap.
     */
    Object saveData();

    /**
     * Function loading saved data into to data structure.
     */
    void loadData(Object data);

    /**
     * Function that should handle the update of the data in the class so it's up to date with the
     * latest version.
     */
    void upgrade();

    Map<Object, Object> diff(UpgradeableDataHashMap newobj);
}
