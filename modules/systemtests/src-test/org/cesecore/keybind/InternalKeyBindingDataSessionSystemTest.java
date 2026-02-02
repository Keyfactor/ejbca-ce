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
package org.cesecore.keybind;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybinding.InternalKeyBindingDataTestSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;

/**
 * System tests for InternalKeyBindingDataSession
 */

public class InternalKeyBindingDataSessionSystemTest {

    private InternalKeyBindingDataTestSessionRemote internalKeyBindingDataTestSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingDataTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    /**
     * Create a keybinding of a certain type and make sure we can't add another with the same name
     */
    @Test
    public void testIsNameUsedSameType() throws InternalKeyBindingNameInUseException {
        final String bindingName = "testIsNameUsedSameType";
        OcspKeyBinding ocspKeyBinding = new OcspKeyBinding();
        ocspKeyBinding.setKeyPairAlias("foo");
        ocspKeyBinding.setName(bindingName);
        int id = internalKeyBindingDataTestSessionRemote.mergeInternalKeyBinding(ocspKeyBinding);
        try {
            assertTrue("Name was returned as not in use.",
                    internalKeyBindingDataTestSessionRemote.isNameUsed(bindingName));
        } finally {
            internalKeyBindingDataTestSessionRemote.removeInternalKeyBinding(id);
        }
    }

    /**
     * Create a keybinding of a certain type and make sure we can't add another with the same name of a different type
     */
    @Test 
    public void testIsNameUsedDifferentType() throws InternalKeyBindingNameInUseException {
        final String bindingName = "testIsNameUsedDifferentType";
        OcspKeyBinding ocspKeyBinding = new OcspKeyBinding();
        ocspKeyBinding.setKeyPairAlias("foo");
        ocspKeyBinding.setName(bindingName);
        int ocspKeyBindingId = internalKeyBindingDataTestSessionRemote.mergeInternalKeyBinding(ocspKeyBinding);
        try {
            assertTrue("Name was returned as not in use.",
                    internalKeyBindingDataTestSessionRemote.isNameUsed(bindingName));
            //Check that we can't add it as well
            AuthenticationKeyBinding authenticationKeyBinding = new AuthenticationKeyBinding();
            authenticationKeyBinding.setName(bindingName);
            authenticationKeyBinding.setKeyPairAlias("foo");
            assertThrows(InternalKeyBindingNameInUseException.class, () -> {
                int authKeyBindId = internalKeyBindingDataTestSessionRemote.mergeInternalKeyBinding(authenticationKeyBinding);
                internalKeyBindingDataTestSessionRemote.removeInternalKeyBinding(authKeyBindId);
            });
           
        } finally {
            internalKeyBindingDataTestSessionRemote.removeInternalKeyBinding(ocspKeyBindingId);
        }
    }

}
