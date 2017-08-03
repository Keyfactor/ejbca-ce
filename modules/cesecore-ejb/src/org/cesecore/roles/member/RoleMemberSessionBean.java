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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.Role;
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
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;

    /** @return the authorized role */
    private Role lookupRoleAndCheckAuthorization(final AuthenticationToken authenticationToken, final RoleMember roleMember) throws AuthorizationDeniedException {
        // Check existence and authorization of referenced objects
        final Role role = roleSession.getRole(authenticationToken, roleMember.getRoleId());
        if (roleMember.getRoleId() != RoleMember.NO_ROLE && role == null) {
            throw new IllegalStateException("Role with ID " + roleMember.getRoleId() + " was not found, or administrator is not authorized to it");
        }
        if (roleMember.getTokenIssuerId() != RoleMember.NO_ISSUER) {
            // Do more expensive fully correct check if it is potentially issued by a CA
            final AuthenticationTokenMetaData metaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(roleMember.getTokenType());
            final AccessMatchValue accessMatchValue = metaData.getAccessMatchValueIdMap().get(roleMember.getTokenMatchKey());
            if (accessMatchValue.isIssuedByCa()) {
                // According to the meta data, this tokenIssuerId should be interpreted as a CA ID
                final int caId = roleMember.getTokenIssuerId();
                if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAACCESS.resource() + caId)) {
                    throw new AuthorizationDeniedException("CA with ID " + caId + " was not found, or administrator is not authorized to it");
                }
            }
        }
        return role;
    }

    @Override
    public RoleMember persist(final AuthenticationToken authenticationToken, final RoleMember roleMember) throws AuthorizationDeniedException {
        return persist(authenticationToken, roleMember, true);
    }
    
    @Override
    public RoleMember persist(final AuthenticationToken authenticationToken, final RoleMember roleMember, final boolean requireNonImportantRoleMembership)
            throws AuthorizationDeniedException {
        if (roleMember==null) {
            // Successfully did nothing
            return null;
        }
        if (requireNonImportantRoleMembership) {
            assertNonImportantRoleMembership(authenticationToken, roleMember);
        }
        roleSession.assertAuthorizedToRoleMembers(authenticationToken, roleMember.getRoleId(), true);
        RoleMember oldRoleMember = null;
        if (roleMember.getId() != RoleMember.ROLE_MEMBER_ID_UNASSIGNED) {
            // Try to locate an existing RoleMember
            oldRoleMember = roleMemberDataSession.findRoleMember(roleMember.getId());
            // If the role Id will change, assert that we have access to the old value first
            if (oldRoleMember != null && roleMember.getRoleId()!=oldRoleMember.getRoleId()) {
                lookupRoleAndCheckAuthorization(authenticationToken, oldRoleMember);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Persisting a role member with ID " + roleMember.getId() + " and match value '" + roleMember.getTokenMatchValue() + "'");
        }
        final Role role = lookupRoleAndCheckAuthorization(authenticationToken, roleMember);
        normalizeRoleMember(roleMember);
        final RoleMember persistedRoleMember = roleMemberDataSession.persistRoleMember(roleMember);
        final boolean addedRoleMember = (oldRoleMember==null);
        final String tokenType = persistedRoleMember.getTokenType();
        final int tokenMatchKey = persistedRoleMember.getTokenMatchKey();
        final String tokenMatchKeyName = AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(tokenType, tokenMatchKey).name();
        final String msg;
        if (addedRoleMember) {
            msg = InternalResources.getInstance().getLocalizedMessage("authorization.adminadded", persistedRoleMember.getTokenMatchValue(), role.getRoleNameFull());
        } else {
            msg = InternalResources.getInstance().getLocalizedMessage("authorization.adminchanged", persistedRoleMember.getTokenMatchValue(), role.getRoleNameFull());
        }
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        details.put("id", persistedRoleMember.getId());
        if (addedRoleMember || !oldRoleMember.getTokenType().equals(persistedRoleMember.getTokenType())) {
            details.put("tokenType", persistedRoleMember.getTokenType());
        }
        if (addedRoleMember || oldRoleMember.getTokenIssuerId()!=persistedRoleMember.getTokenIssuerId()) {
            details.put("tokenIssuerId", roleMember.getTokenIssuerId());
        }
        if (addedRoleMember || oldRoleMember.getTokenMatchKey()!=persistedRoleMember.getTokenMatchKey()) {
            details.put("tokenMatchKey", tokenMatchKeyName + " (" + persistedRoleMember.getTokenMatchKey()+ ")");
        }
        if (addedRoleMember || oldRoleMember.getTokenMatchOperator()!=persistedRoleMember.getTokenMatchOperator()) {
            details.put("tokenMatchOperator", persistedRoleMember.getAccessMatchType().name() + " (" + persistedRoleMember.getTokenMatchOperator()+ ")");
        }
        if (addedRoleMember || !StringUtils.equals(oldRoleMember.getTokenMatchValue(), persistedRoleMember.getTokenMatchValue())) {
            details.put("tokenMatchValue", persistedRoleMember.getTokenMatchValue());
        }
        if (addedRoleMember || oldRoleMember.getRoleId()!=persistedRoleMember.getRoleId()) {
            details.put("roleId", roleMember.getRoleId());
            details.put("nameSpace", role.getNameSpace());
            details.put("roleName", role.getRoleName());
        }
        if (addedRoleMember || !StringUtils.equals(oldRoleMember.getDescription(), persistedRoleMember.getDescription())) {
            details.put("description", persistedRoleMember.getDescription());
        }
        final EventType eventType = addedRoleMember ? EventTypes.ROLE_ACCESS_USER_ADDITION : EventTypes.ROLE_ACCESS_USER_CHANGE;
        securityEventsLoggerSession.log(eventType, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE, authenticationToken.toString(), null, null, null, details);
        return persistedRoleMember;
    }
    
    /**
     * Normalizes data in the role member, e.g. changing serial numbers to uppercase without leading zeros.
     * @param roleMember
     */
    private void normalizeRoleMember(final RoleMember roleMember) {
        final AccessMatchValue matchKey = AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(roleMember.getTokenType(), roleMember.getTokenMatchKey());
        if (matchKey != null) {
            roleMember.setTokenMatchValue(matchKey.normalizeMatchValue(roleMember.getTokenMatchValue()));
        }
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
        lookupRoleAndCheckAuthorization(authenticationToken, roleMember);
        return roleMember;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<RoleMember> getRoleMembersByRoleId(final AuthenticationToken authenticationToken, final int roleId) throws AuthorizationDeniedException {
        // Ensure that the role exists and that the caller is authorized to it
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.VIEWROLES.resource())) {
            final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.notauthorizedtoviewroles", authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
        if (roleSession.getRole(authenticationToken, roleId)==null) {
            return null;
        }
        final List<RoleMember> ret = new ArrayList<>();
        final Set<String> requiredCaAccessResources = new HashSet<>();
        for (final RoleMemberData roleMemberData : roleMemberDataSession.findByRoleId(roleId)) {
            final RoleMember roleMember = roleMemberData.asValueObject();
            final AuthenticationTokenMetaData metaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(roleMember.getTokenType());
            if (metaData.getAccessMatchValueIdMap().get(roleMember.getTokenMatchKey()).isIssuedByCa()) {
                requiredCaAccessResources.add(StandardRules.CAACCESS.resource() + roleMember.getTokenIssuerId());
            }
            ret.add(roleMember);
        }
        final String[] requiredCaAccessResourcesArray = requiredCaAccessResources.toArray(new String[requiredCaAccessResources.size()]);
        if (!requiredCaAccessResources.isEmpty() && !authorizationSession.isAuthorizedNoLogging(authenticationToken, requiredCaAccessResourcesArray)) {
            throw new AuthorizationDeniedException("Not authorized to all members in role.");
        }
        return ret;
    }

    /** @throws AuthorizationDeniedException if the provided RoleMember is the only member in the particular RoleMember's Role matching the authentication token */
    private void assertNonImportantRoleMembership(final AuthenticationToken authenticationToken, final RoleMember roleMember) throws AuthorizationDeniedException {
        final List<RoleMember> roleMembers = getRoleMembersByRoleId(authenticationToken, roleMember.getRoleId());
        int count = 0;
        for (final RoleMember current : roleMembers) {
            if (current.getTokenType().equals(roleMember.getTokenType()) &&
                    current.getTokenIssuerId()==roleMember.getTokenIssuerId() &&
                    current.getTokenMatchKey()==roleMember.getTokenMatchKey() &&
                    current.getTokenMatchOperator()==roleMember.getTokenMatchOperator() &&
                    StringUtils.equals(current.getTokenMatchValue(), roleMember.getTokenMatchValue())) {
                count++;
            }
        }
        // If there are no duplicate matches for this RoleMember...
        if (count<2) {
            if (log.isDebugEnabled()) {
                log.debug("No RoleMember provides the same match as the one with id " + roleMember.getId() + ". count="+count);
            }
            // ...and the caller relies on this match for access the access granted by this Role...
            for (final RoleMember current : roleMemberDataSession.getRoleMembersMatchingAuthenticationToken(authenticationToken)) {
                if (roleMember.getId() == current.getId()) {
                    if (log.isDebugEnabled()) {
                        log.debug("'"+authenticationToken+"' relies on match from RoleMember with id " + roleMember.getId() + ".");
                    }
                    // ...also check if there are other roles that would provide the same access as a this Role
                    roleSession.assertNonImportantRoleMembership(authenticationToken, roleMember.getRoleId());
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("RoleMembers provides the same match as the one with id " + roleMember.getId() + ". count="+count);
            }
        }
    }
    
    @Override
    public boolean remove(final AuthenticationToken authenticationToken, final int roleMemberId) throws AuthorizationDeniedException {
        final RoleMember roleMember = roleMemberDataSession.findRoleMember(roleMemberId);
        if (roleMember == null) {
            return false;
        }
        assertNonImportantRoleMembership(authenticationToken, roleMember);
        roleSession.assertAuthorizedToRoleMembers(authenticationToken, roleMember.getRoleId(), true);
        final Role role = lookupRoleAndCheckAuthorization(authenticationToken, roleMember);
        final boolean removed = roleMemberDataSession.remove(roleMemberId);
        if (removed) {
            final String tokenType = roleMember.getTokenType();
            final int tokenMatchKey = roleMember.getTokenMatchKey();
            final String tokenMatchKeyName = AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(tokenType, tokenMatchKey).name();
            final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.adminremoved", roleMember.getTokenMatchValue(), role.getRoleNameFull());
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            details.put("id", roleMember.getId());
            details.put("tokenType", roleMember.getTokenType());
            details.put("tokenIssuerId", roleMember.getTokenIssuerId());
            details.put("tokenMatchKey", tokenMatchKeyName + " (" + roleMember.getTokenMatchKey()+ ")");
            details.put("tokenMatchOperator", roleMember.getAccessMatchType().name() + " (" + roleMember.getTokenMatchOperator()+ ")");
            details.put("tokenMatchValue", roleMember.getTokenMatchValue());
            details.put("roleId", roleMember.getRoleId());
            details.put("nameSpace", role.getNameSpace());
            details.put("roleName", role.getRoleName());
            details.put("description", roleMember.getDescription());
            securityEventsLoggerSession.log(EventTypes.ROLE_ACCESS_USER_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
        return removed;
    }
}
