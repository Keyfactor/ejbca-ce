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
 * Object and name to id lookup cache interface.
 * 
 * @version $Id$
 */
public interface CommonCache<T> {

    /** @return cached Object or null if none is present. */
    T getEntry(int id);

    /** @return true when the cache for this object has expired or the token is non-existing. */
    boolean shouldCheckForUpdates(int id);

    /** Update the cache with the current version read from the database. */
    void updateWith(int id, int digest, String name, T object);

    /** Remove the specified entry from the cache and mapping if it exists. */
    void removeEntry(int id);

    /** @return a copy of the id to name map as a name to id map*/
    Map<String, Integer> getNameToIdMap();

    /** Remove all references from this cache */
    void flush();
}
