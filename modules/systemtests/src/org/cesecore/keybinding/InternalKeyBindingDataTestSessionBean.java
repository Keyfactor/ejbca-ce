/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class InternalKeyBindingDataTestSessionBean implements InternalKeyBindingDataTestSessionRemote {

    @EJB
    private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
    
    @Override
    public boolean isNameUsed(String name, String type) {
        return internalKeyBindingDataSession.isNameUsed(name, type);
    }

    @Override
    public int mergeInternalKeyBinding(InternalKeyBinding internalKeyBinding) throws InternalKeyBindingNameInUseException {
        return internalKeyBindingDataSession.mergeInternalKeyBinding(internalKeyBinding);
    }

    @Override
    public boolean removeInternalKeyBinding(int id) {
        return internalKeyBindingDataSession.removeInternalKeyBinding(id);
    }

}
