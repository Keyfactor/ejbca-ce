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
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleMemberProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleMemberProxySessionBean implements RoleMemberProxySessionRemote {

    @EJB
    private RoleMemberSessionLocal roleMemberSession;
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @Override
    public int createOrEdit(RoleMember roleMember) {
        return roleMemberSession.createOrEdit(new RoleMemberData(roleMember.getId(), roleMember.getTokenType(), roleMember.getTokenIssuerId(),
                roleMember.getTokenMatchKey(), roleMember.getTokenMatchOperator(), roleMember.getTokenMatchValue(),
                roleMember.getRoleId(), roleMember.getMemberBindingType(), roleMember.getMemberBindingValue()));
    }

    @Override
    public boolean remove(int primaryKey) {
        return roleMemberSession.remove(primaryKey);
    }

    @Override
    public int createOrEdit(RoleMemberData roleMember) {
        return roleMemberSession.createOrEdit(roleMember);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public RoleMember findRoleMember(int primaryKey) {
        return roleMemberSession.findRoleMember(primaryKey);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<RoleMember> findRoleMemberByRoleId(int roleId) {
        return roleMemberSession.findRoleMemberByRoleId(roleId);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isNewAuthorizationPatternMarkerPresent() {
        return accessTreeUpdateSession.isNewAuthorizationPatternMarkerPresent();
    }
}
