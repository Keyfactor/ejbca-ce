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
package org.ejbca.core.ejb.keybind;

import java.util.List;
import java.util.Map;

import javax.ejb.Local;

/**
 * Create Read Update Delete (CRUD) interface for InternalKeyBindingData.
 * 
 * @version $Id$
 */
@Local
public interface InternalKeyBindingDataSessionLocal {

    /** @return the specified InternalKeyBinding */
    InternalKeyBinding getInternalKeyBinding(int id);

    /** Add the specified InternalKeyBinding to the database and return the id used to store it */
    int mergeInternalKeyBinding(InternalKeyBinding internalKeyBinding) throws InternalKeyBindingNameInUseException;

    /** @return true if the object existed before removal of the object with the provided id from the database. */
    boolean removeInternalKeyBinding(int id);

    /** @return a list of all identifiers for the specified type from the database. If the type is null, ids for all types will be returned. */
    List<Integer> getIds(String type);

    /** @return a (copy of a) name to id lookup table */
    Map<String, Integer> getCachedNameToIdMap();

    /** Clears the InternalKeyBinding cache. */
    void flushCache();

    /** @return true if the specified name is already in use by another InternalKeyBinding (checks the database, not the cache) */
    boolean isNameUsed(String name);

    /** @return true if the specified name is used by exactly one InternalKeyBinding and that object has the same id (checks the database, not the cache) */
    boolean isNameUsedByIdOnly(String name, int id);

}
