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
package org.cesecore.roles.member;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class RoleMemberDataSessionTest {

    private RoleMemberProxySessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    /**
     * Simple sanity test, meant to involve other session beans as little as possible.
     */
    @Test
    public void testCrudOperations() {
        final RoleMemberData roleMember = new RoleMemberData(X500PrincipalAccessMatchValue.WITH_COUNTRY, "SE", null, null, null);
        assertNull("accessUserAspectManagerSession.find did not return null for a non existing object.",
                roleMemberSession.find(0));
        int roleMemberId = -1;
        try {
            roleMemberId = roleMemberSession.createOrEdit(roleMember);
            RoleMemberData createdRoleMember = roleMemberSession.find(roleMemberId);
            assertNotNull("Role Member was not persisted sucessfully", createdRoleMember);
            createdRoleMember.setValue("DE");
            roleMemberSession.createOrEdit(createdRoleMember);
            RoleMemberData editedRoleMember = roleMemberSession.find(roleMemberId);
            assertEquals("Role Member was not sucessfully edited.", "DE", editedRoleMember.getValue());

        } finally {
            roleMemberSession.remove(roleMemberId);
            assertNull("AccessUserAspectManagerSessionRemote did not properly remove an object.",  roleMemberSession.find(roleMemberId));
        }
    }
}
