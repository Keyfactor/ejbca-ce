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

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.jndi.JndiConstants;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleMemberDataProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleMemberDataProxySessionBean implements RoleMemberDataProxySessionRemote {

    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @Override
    public int createOrEdit(RoleMember roleMember) {
        return roleMemberDataSession.persistRoleMember(roleMember).getId();
    }

    @Override
    public boolean remove(int primaryKey) {
        return roleMemberDataSession.remove(primaryKey);
    }

    @Override
    public int createOrEdit(RoleMemberData roleMemberData) {
        return roleMemberDataSession.persistRoleMember(roleMemberData.asValueObject()).getId();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public RoleMember findRoleMember(int primaryKey) {
        return roleMemberDataSession.findRoleMember(primaryKey);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<RoleMember> findRoleMemberByRoleId(int roleId) {
        return roleMemberDataSession.findRoleMemberByRoleId(roleId);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isNewAuthorizationPatternMarkerPresent() {
        return accessTreeUpdateSession.isNewAuthorizationPatternMarkerPresent();
    }
}
