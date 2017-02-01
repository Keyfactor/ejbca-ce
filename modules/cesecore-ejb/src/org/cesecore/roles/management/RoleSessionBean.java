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
package org.cesecore.roles.management;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.time.TrustedTimeWatcherSessionLocal;

/**
 * Implementation of the RoleSession interfaces.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleSessionBean implements RoleSessionLocal, RoleSessionRemote {

    //private static final Logger log = Logger.getLogger(RoleSessionBean.class);

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private TrustedTimeWatcherSessionLocal trustedTimeWatcherSession;
    @EJB
    private RoleDataSessionLocal roleDataSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final AuthenticationToken authenticationToken, final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        final Role role = roleDataSession.getRole(nameSpace, roleName);
        if (role!=null) {
            assertAuthorizedToAllAccessRules(authenticationToken, role); // Leaks existence of roleId
        }
        return role;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final AuthenticationToken authenticationToken, final int roleId) throws AuthorizationDeniedException {
        final Role role = roleDataSession.getRole(roleId);
        if (role!=null) {
            assertAuthorizedToAllAccessRules(authenticationToken, role); // Leaks existence of roleId
        }
        return role;
    }

    @Override
    public boolean deleteRoleIdempotent(final AuthenticationToken authenticationToken, final int roleId) throws AuthorizationDeniedException {
        assertAuthorizedToEditRoles(authenticationToken);
        final Role role = roleDataSession.getRole(roleId);
        if (role==null) {
            return false;
        }
        // Check that authenticationToken is allowed to remove the role with all its rights
        assertAuthorizedToAllAccessRules(authenticationToken, role);
        assertNotMemberAndAuthorizedToNameSpace(authenticationToken, role);
        boolean ret = roleDataSession.deleteRoleNoAuthorizationCheck(role.getRoleId());
        RoleCache.INSTANCE.updateWith(role.getRoleId(), 0, null, null);
        final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.roleremoved", role.getRoleNameFull());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        details.put("roleId", role.getRoleId());
        details.put("roleName", role.getRoleName());
        details.put("nameSpace", role.getNameSpace());
        securityEventsLoggerSession.log(EventTypes.ROLE_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                authenticationToken.toString(), null, null, null, details);
        final List<RoleMember> roleMembers = roleMemberSession.findRoleMemberByRoleId(role.getRoleId());
        for (final RoleMember roleMember : roleMembers) {
            ret |= roleMemberSession.remove(roleMember.getId());
        }
        return ret;
    }

    @Override
    public Role persistRole(final AuthenticationToken authenticationToken, final Role role) throws RoleExistsException, AuthorizationDeniedException {
        // Normalize and minimize access rules before checking authorization
        role.normalizeAccessRules();
        role.minimizeAccessRules();
        // Check if the caller is authorized to edit roles in general
        assertAuthorizedToEditRoles(authenticationToken);
        // Is the authToken authorized to the role as provided as an argument?
        assertAuthorizedToAllAccessRules(authenticationToken, role);
        assertNotMemberAndAuthorizedToNameSpace(authenticationToken, role);
        // Is the authToken authorized to the role found by id in the database?
        final Role roleById = role.getRoleId()==Role.ROLE_ID_UNASSIGNED ? null : roleDataSession.getRole(role.getRoleId());
        if (roleById!=null) {
            assertAuthorizedToAllAccessRules(authenticationToken, roleById);
        }
        // Sort access rules to make raw xml editing (e.g. statedump) easier
        role.sortAccessRules();
        final Role roleByName = roleDataSession.getRole(role.getNameSpace(), role.getRoleName());
        if (roleById == null) {
            if (roleByName!=null) {
                throw new RoleExistsException(InternalResources.getInstance().getLocalizedMessage("authorization.erroraddroleexists", role.getRoleNameFull()));
            }
            // Persist new role
            role.setRoleId(roleDataSession.persistRole(role));
            final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.roleadded", role.getRoleName());
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            details.put("roleId", role.getRoleId());
            details.put("roleName", role.getRoleName());
            details.put("nameSpace", role.getNameSpace());
            securityEventsLoggerSession.log(EventTypes.ROLE_CREATION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        } else {
            // Save to existing role
            if (roleByName==null) {
                // Audit log that the role will be renamed when persisted
                final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.rolerenamed", roleById.getRoleNameFull(),
                        role.getRoleNameFull());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("roleId", role.getRoleId());
                details.put("roleNameOld", roleById.getRoleName());
                details.put("roleNameNew", role.getRoleName());
                details.put("nameSpaceOld", roleById.getNameSpace());
                details.put("nameSpaceNew", role.getNameSpace());
                securityEventsLoggerSession.log(EventTypes.ROLE_RENAMING, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                        authenticationToken.toString(), null, null, null, details);
            } else {
                if (roleByName.getRoleId() != role.getRoleId()) {
                    throw new RoleExistsException("A role with the same name exists.");
                }
            }
            // Persist data changes
            roleDataSession.persistRole(role);
        }
        // Audit log access rule changes (also for new roles)
        final HashMap<String, Boolean> newAccessRules = role.getAccessRules();
        final HashMap<String, Boolean> oldAccessRules = roleById==null ? new HashMap<String, Boolean>() : roleById.getAccessRules();
        final Map<Object,Object> oldAuditMap = new HashMap<>();
        for (final Entry<String,Boolean> entry : oldAccessRules.entrySet()) {
            oldAuditMap.put(entry.getKey(), entry.getValue().booleanValue() ? "allow" : "deny");
        }
        final Map<Object,Object> newAuditMap = new HashMap<>();
        for (final Entry<String,Boolean> entry : newAccessRules.entrySet()) {
            newAuditMap.put(entry.getKey(), entry.getValue().booleanValue() ? "allow" : "deny");
        }
        final Map<Object, Object> auditLogDiffMap = UpgradeableDataHashMap.diffMaps(oldAuditMap, newAuditMap);
        final StringBuilder rulesMsg = new StringBuilder();
        for (Map.Entry<Object, Object> entry : auditLogDiffMap.entrySet()) {
            rulesMsg.append("[" + entry.getKey().toString() + ":"+entry.getValue().toString()+"]");
        }
        final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.accessruleschanged", role.getRoleNameFull(), rulesMsg.toString());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        details.put("roleId", role.getRoleId());
        details.put("roleName", role.getRoleName());
        details.put("nameSpace", role.getNameSpace());
        securityEventsLoggerSession.log(EventTypes.ROLE_ACCESS_RULE_CHANGE, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                authenticationToken.toString(), null, null, null, details);
        return role;
    }

    /**
     * Asserts that authentication token is authorized to edit roles in general. 
     * 
     * @param authenticationToken a token for the authenticating entity
     * @throws AuthorizationDeniedException if not authorized
     */
    private void assertAuthorizedToEditRoles(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(authenticationToken, StandardRules.EDITROLES.resource())) {
            String msg = InternalResources.getInstance().getLocalizedMessage("authorization.notauthorizedtoeditroles", authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }

    /** @throws AuthorizationDeniedException if the caller is not authorized to one of the rules granted access to (even implied) by this role */
    private void assertAuthorizedToAllAccessRules(final AuthenticationToken authenticationToken, final Role role) throws AuthorizationDeniedException {
        // Verify that authenticationToken has access to every single added allow access rule
        for (final Entry<String, Boolean> entry : role.getAccessRules().entrySet()) {
            if (entry.getValue().booleanValue()) {
                if (!authorizationSession.isAuthorized(authenticationToken, entry.getKey())) {
                    // Role would allow what is is not granted to current authenticationToken
                    throw new AuthorizationDeniedException("Not authorized to all access rules in role.");
                }
            }
        }
        // Verify that role does not have access to any rule that is denied to this authenticationToken
        try {
            final Set<Integer> roleIdsCallerBelongsTo = roleMemberSession.getRoleIdsMatchingAuthenticationToken(authenticationToken);
            HashMap<String, Boolean> totalAccessRules = new HashMap<>();
            for (final int roleId : roleIdsCallerBelongsTo) {
                totalAccessRules = AccessRulesHelper.getAccessRulesUnion(totalAccessRules, roleDataSession.getRole(roleId).getAccessRules());
            }
            for (final Entry<String, Boolean> entry : totalAccessRules.entrySet()) {
                if (!entry.getValue().booleanValue()) {
                    if (role.hasAccessToResource(entry.getKey())) {
                        // Role would allow what is denied to current authenticationToken
                        throw new AuthorizationDeniedException("Not authorized to all access rules in role.");
                    }
                }
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthorizationDeniedException("Not authorized to all access rules in role.");
        }
    }
    
    /** @throws AuthorizationDeniedException if the caller part of this role (to prevent suicide) or if the nameSpace is not "owned" by the caller. */
    private void assertNotMemberAndAuthorizedToNameSpace(final AuthenticationToken authenticationToken, final Role role) throws AuthorizationDeniedException {
        final int roleId = role.getRoleId();
        try {
            final Set<Integer> roleIdsCallerBelongsTo = roleMemberSession.getRoleIdsMatchingAuthenticationToken(authenticationToken);
            if (roleId!=Role.ROLE_ID_UNASSIGNED) {
                // Check that authenticationToken is not about to lock itself out by modifying its own role
                if (roleIdsCallerBelongsTo.contains(role.getRoleId())) {
                    throw new AuthorizationDeniedException("Current AuthenticationToken belongs to this role.");
                }
            }
            // Assert that AuthenticationToken is allowed to mess with the role's nameSpace
            if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource())) {
                final Set<String> ownedNameSpaces = new HashSet<>();
                for (final int current : roleIdsCallerBelongsTo) {
                    ownedNameSpaces.add(roleDataSession.getRole(current).getNameSpace());
                }
                if (!ownedNameSpaces.contains("") && !ownedNameSpaces.contains(role.getNameSpace())) {
                    throw new AuthorizationDeniedException("Current AuthenticationToken is not authorized to the namespace '"+role.getNameSpace()+"'.");
                }
            }
        } catch (AuthenticationFailedException e) {
            throw new AuthorizationDeniedException("Current AuthenticationToken is not authorized to the namespace '"+role.getNameSpace()+"'.");
        }
    }
}
