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

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.management.RoleSessionLocal;

/**
 * @see RoleMemberSessionRemote
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleMemberSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleMemberSessionBean implements RoleMemberSessionLocal, RoleMemberSessionRemote {

    private static final Logger log = Logger.getLogger(RoleMemberSessionBean.class);

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleDataSessionLocal roleDataSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;

    
    private void checkRoleAuth(final AuthenticationToken authenticationToken, final RoleMember roleMember) throws AuthorizationDeniedException {
        // Check existence and authorization of referenced objects 
        if (roleMember.getRoleId() != RoleMember.NO_ROLE && roleSession.getRole(authenticationToken, roleMember.getRoleId()) == null) {
            throw new IllegalStateException("Role with ID " + roleMember.getRoleId() + " was not found, or administrator is not authorized to it");
        }
        if (roleMember.getTokenIssuerId() != RoleMember.NO_ISSUER) {
            if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAACCESS.resource() + roleMember.getTokenIssuerId())) {
                throw new AuthorizationDeniedException("CA with ID " + roleMember.getTokenIssuerId() + " was not found, or administrator is not authorized to it");
            }
        }
    }
    
    @Override
    public int createOrEdit(final AuthenticationToken authenticationToken, final RoleMember roleMember) throws AuthorizationDeniedException {
        roleSession.assertAuthorizedToRoleMembers(authenticationToken, roleMember.getRoleId(), true);
        
        final RoleMemberData roleMemberData;
        if (roleMember.getId() != RoleMember.ROLE_MEMBER_ID_UNASSIGNED) {
            roleMemberData = roleMemberDataSession.find(roleMember.getId());
            if (roleMemberData == null) {
                return RoleMember.ROLE_MEMBER_ID_UNASSIGNED;
            }
            checkRoleAuth(authenticationToken, roleMemberData.asValueObject());
        } else {
            roleMemberData = new RoleMemberData();
        }
        
        checkRoleAuth(authenticationToken, roleMember);
        roleMemberData.updateValuesFromValueObject(roleMember);
        
        if (log.isDebugEnabled()) {
            log.debug("Persisting a role member with ID " + roleMember.getRoleId() + " and match value '" + roleMember.getTokenMatchValue() + "'");
        }
        return roleMemberDataSession.createOrEdit(roleMemberData);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public RoleMember getRoleMember(final AuthenticationToken authenticationToken, final int roleMemberId) throws AuthorizationDeniedException {
        final RoleMember roleMember = roleMemberDataSession.findRoleMember(roleMemberId);
        if (roleMember == null) {
            return null;
        }
        // Authorization checks
        roleSession.assertAuthorizedToRoleMembers(authenticationToken, roleMember.getRoleId(), false);
        checkRoleAuth(authenticationToken, roleMember);
        return roleMember;
    }
    
    @Override
    public boolean remove(final AuthenticationToken authenticationToken, final int roleMemberId) throws AuthorizationDeniedException {
        final RoleMember roleMember = roleMemberDataSession.findRoleMember(roleMemberId);
        if (roleMember == null) {
            return false;
        }
        roleSession.assertAuthorizedToRoleMembers(authenticationToken, roleMember.getRoleId(), true);
        checkRoleAuth(authenticationToken, roleMember);
        return roleMemberDataSession.remove(roleMemberId);
    }

}
