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

import java.util.List;
import java.util.Map;

/**
 * Object and name to id lookup cache interface.
 * 
 * @version $Id$
 */
public interface CommonCache<T> {

    /** @return cached Object or null if none is present. */
    T getEntry(Integer id);

    /** @return cached Object or null if none is present. */
    T getEntry(int id);

    /** @return true when the cache for this object has expired or the token is non-existing. */
    boolean shouldCheckForUpdates(int id);

    /** Update the cache with the current version read from the database. 
     *
     * @param id id of the object, typically database id
     * @param digest typically getProtectString(0).hashCode() of the object;
     * @name String name of the object, typically database name
     * @object the object to cache
     */
    void updateWith(int id, int digest, String name, T object);

    /** this method exposes the loginc inside updateWith that determines if an object is the same as the cached object.
     * If the objects are the same, updateWith will not update the object as an optimization. This method can be used to skip expensive object creation
     * if the objects are anyway the same and updateWith will not end up doing anything
     * @param id id of the object, typically database id
     * @param digest, typically getProtectString(0).hashCode() of the object;
     * @return true if a call to updateWith will perform an actual cache update
     */
    boolean willUpdate(int id, int digest);

    /** Remove the specified entry from the cache and mapping if it exists. */
    void removeEntry(int id);

    /** Provides functionality of an IdToNameMap. 
     * @return return the name from the entry, given the id, or null if it does not exist.
     */
    String getName(int id);

    /** @return a copy of the id to name map as a name to id map */
    Map<String, Integer> getNameToIdMap();

    /** Remove all references from this cache */
    void flush();
    
    /** Replace cache with the entries referenced in keys */
    void replaceCacheWith(List<Integer> keys);
}
