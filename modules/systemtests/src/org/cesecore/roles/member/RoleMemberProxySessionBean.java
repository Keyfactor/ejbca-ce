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
package org.cesecore.roles.member;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleMemberProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleMemberProxySessionBean implements RoleMemberProxySessionRemote {

    @EJB
    private RoleMemberSessionLocal roleMemberSession;

    @Override
    public int createOrEdit(RoleMemberData roleMember) {
        return roleMemberSession.createOrEdit(roleMember);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public RoleMemberData find(int primaryKey) {
        return roleMemberSession.find(primaryKey);
    }

    @Override
    public void remove(RoleMemberData roleMember) {
        roleMemberSession.remove(roleMember);
    }

    @Override
    public void remove(int primaryKey) {
        roleMemberSession.remove(primaryKey);
    }

}
