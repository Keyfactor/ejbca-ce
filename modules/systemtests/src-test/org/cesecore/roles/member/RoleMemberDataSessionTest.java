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

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.Test;

/**
 * @version $Id$
 */
public class RoleMemberDataSessionTest {

    private RoleMemberProxySessionRemote roleMemberProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    /**
     * Simple sanity test, meant to involve other session beans as little as possible.
     */
    @Test
    public void testCrudOperations() {      
        assertNull("accessUserAspectManagerSession.find did not return null for a non existing object.",
                roleMemberProxySession.findRoleMember(0));
        final RoleMemberData roleMember = new RoleMemberData(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, X500PrincipalAccessMatchValue.WITH_COUNTRY.getTokenType(),
                RoleMember.NO_ISSUER, X500PrincipalAccessMatchValue.WITH_COUNTRY.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(), "SE", RoleMember.NO_ROLE, null, null);
        int roleMemberId = -1;
        try {
            roleMemberId = roleMemberProxySession.createOrEdit(roleMember);
            RoleMember createdRoleMember = roleMemberProxySession.findRoleMember(roleMemberId);
            assertNotNull("Role Member was not persisted sucessfully", createdRoleMember);
            createdRoleMember.setTokenMatchValue("DE");
            roleMemberProxySession.createOrEdit(createdRoleMember);
            RoleMember editedRoleMember = roleMemberProxySession.findRoleMember(roleMemberId);
            assertEquals("Role Member was not sucessfully edited.", "DE", editedRoleMember.getTokenMatchValue());

        } finally {
            roleMemberProxySession.remove(roleMemberId);
            assertNull("AccessUserAspectManagerSessionRemote did not properly remove an object.",  roleMemberProxySession.findRoleMember(roleMemberId));
        }
    }
}
