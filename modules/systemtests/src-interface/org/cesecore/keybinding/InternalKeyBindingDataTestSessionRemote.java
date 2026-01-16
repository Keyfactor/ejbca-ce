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
package org.cesecore.keybinding;

import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;

import jakarta.ejb.Remote;

@Remote
public interface InternalKeyBindingDataTestSessionRemote {

    /** @return true if the specified name is already in use by another InternalKeyBinding of the same type (checks the database, not the cache) */
    boolean isNameUsed(final String name, final String type);
    
    /** Add the specified InternalKeyBinding to the database and return the id used to store it */
    int mergeInternalKeyBinding(InternalKeyBinding internalKeyBinding) throws InternalKeyBindingNameInUseException;
    
    /** @return true if the object existed before removal of the object with the provided id from the database. */
    boolean removeInternalKeyBinding(int id);

}
