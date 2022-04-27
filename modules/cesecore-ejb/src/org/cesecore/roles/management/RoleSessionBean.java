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

import java.util.ArrayList;
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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.LocalJvmOnlyAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberData;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;

/**
 * Implementation of the RoleSession interfaces.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleSessionBean implements RoleSessionLocal, RoleSessionRemote {

    private static final Logger log = Logger.getLogger(RoleSessionBean.class);

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private RoleDataSessionLocal roleDataSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final AuthenticationToken authenticationToken, final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        final Role role = roleDataSession.getRole(nameSpace, roleName);
        if (role!=null) {
            final Set<Integer> roleIdsCallerBelongsTo = roleMemberDataSession.getRoleIdsMatchingAuthenticationToken(authenticationToken);
            assertAuthorizedToAllAccessRules(authenticationToken, role, roleIdsCallerBelongsTo);
            assertAuthorizedToNameSpace(authenticationToken, role, roleIdsCallerBelongsTo);
        }
        // Always return a copy to prevent shared access
        return role==null ? null : new Role(role);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final AuthenticationToken authenticationToken, final int roleId) throws AuthorizationDeniedException {
        final Role role = roleDataSession.getRole(roleId);
        if (role!=null) {
            final Set<Integer> roleIdsCallerBelongsTo = roleMemberDataSession.getRoleIdsMatchingAuthenticationToken(authenticationToken);
            assertAuthorizedToAllAccessRules(authenticationToken, role, roleIdsCallerBelongsTo);
            assertAuthorizedToNameSpace(authenticationToken, role, roleIdsCallerBelongsTo);
        }
        // Always return a copy to prevent shared access
        return role==null ? null : new Role(role);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<Role> getRolesAuthenticationTokenIsMemberOf(final AuthenticationToken authenticationToken) {
        final List<Role> roles = new ArrayList<>();
        for (final int roleId : roleMemberDataSession.getRoleIdsMatchingAuthenticationToken(authenticationToken)) {
            roles.add(roleDataSession.getRole(roleId));
        }
        return roles;
    }

    /*
     * NOTE: This separate method for remote EJB calls exists for a good reason: If this is invoked as a part of a
     * local transaction, the LocalJvmOnlyAuthenticationToken will be valid for subsequent authentication calls.
     */
    @Override
    public List<Role> getRolesAuthenticationTokenIsMemberOfRemote(AuthenticationToken authenticationTokenForAuhtorization, AuthenticationToken authenticationTokenToCheck) {
        if (authenticationTokenToCheck instanceof LocalJvmOnlyAuthenticationToken) {
            // Ensure that the matching procedure below also works for remote EJB calls
            ((LocalJvmOnlyAuthenticationToken) authenticationTokenToCheck).initRandomToken();
        }
        final List<Role> roles = getRolesAuthenticationTokenIsMemberOf(authenticationTokenToCheck);
        roles.retainAll(getAuthorizedRoles(authenticationTokenForAuhtorization));
        return roles;
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<Role> getAuthorizedRolesWithAccessToResource(final AuthenticationToken authenticationToken, final String resource) {
        final List<Role> roles = new ArrayList<>();
        for (final Role role : getAuthorizedRoles(authenticationToken)) {
            if (AccessRulesHelper.hasAccessToResource(role.getAccessRules(), resource)) {
                roles.add(role);
            }
        }
        return roles;
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<Role> getAuthorizedRoles(final AuthenticationToken authenticationToken) {
        final List<Role> roles = new ArrayList<>();
        final Set<Integer> roleIdsCallerBelongsTo = roleMemberDataSession.getRoleIdsMatchingAuthenticationToken(authenticationToken);
        for (final Role role : roleDataSession.getAllRoles()) {
            // Verify that the caller is authorized to role's namespace
            if (!isAuthorizedToNameSpace(authenticationToken, role, roleIdsCallerBelongsTo)) {
                if (log.isDebugEnabled()) {
                    log.debug("'" + authenticationToken.toString() + "' is not authorized to the namespace '"+role.getNameSpace()+"'.");
                }
                continue;
            }
            // Verify that the caller is authorized to all access rules in this role
            if (!isAuthorizedToAllAccessRules(authenticationToken, role, roleIdsCallerBelongsTo)) {
                if (log.isDebugEnabled()) {
                    log.debug("'" + authenticationToken.toString() + "' is not authorized to all access rules in role '"+role.getRoleNameFull()+"'.");
                }
                continue;
            }
            // Verify that the caller is authorized to all CAs that are issuers of members in this role
            if (!isAuthorizedToAllRoleMembersIssuers(authenticationToken, role.getRoleId())) {
                if (log.isDebugEnabled()) {
                    log.debug("'" + authenticationToken.toString() + "' is not authorized to all members in role '"+role.getRoleNameFull()+"'.");
                }
                continue;
            }
            roles.add(role);
        }
        return roles;
    }

    @Override
    public boolean deleteRoleIdempotent(final AuthenticationToken authenticationToken, final int roleId) throws AuthorizationDeniedException {
        assertAuthorizedToEditRoles(authenticationToken);
        final Role role = roleDataSession.getRole(roleId);
        if (role==null) {
            return false;
        }
        // Check that authenticationToken is allowed to remove the role with all its rights
        final Set<Integer> roleIdsCallerBelongsTo = roleMemberDataSession.getRoleIdsMatchingAuthenticationToken(authenticationToken);
        assertAuthorizedToAllAccessRules(authenticationToken, role, roleIdsCallerBelongsTo);
        assertAuthorizedToNameSpace(authenticationToken, role, roleIdsCallerBelongsTo);
        assertNonImportantRoleMembership(authenticationToken, role, roleIdsCallerBelongsTo);
        boolean ret = roleDataSession.deleteRoleNoAuthorizationCheck(role.getRoleId());
        RoleCache.INSTANCE.updateWith(role.getRoleId(), 0, null, null);
        final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.roleremoved", role.getRoleNameFull());
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        details.put("roleId", role.getRoleId());
        details.put("roleName", role.getRoleName());
        details.put("nameSpace", role.getNameSpace());
        securityEventsLoggerSession.log(EventTypes.ROLE_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                authenticationToken.toString(), null, null, null, details);
        final List<RoleMember> roleMembers = roleMemberDataSession.findRoleMemberByRoleId(role.getRoleId());
        for (final RoleMember roleMember : roleMembers) {
            ret |= roleMemberDataSession.remove(roleMember.getId());
        }
        return ret;
    }

    @Override
    public boolean deleteRoleIdempotent(final AuthenticationToken authenticationToken, final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        boolean roleDeleted = false;
        while (true) {
            final Role role = getRole(authenticationToken, nameSpace, roleName);
            if (role == null) {
                return roleDeleted;
            }
            roleDeleted |= deleteRoleIdempotent(authenticationToken, role.getRoleId());
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void assertAuthorizedToRoleMembers(final AuthenticationToken authenticationToken, final int roleId, final boolean requireEditAccess) throws AuthorizationDeniedException {
        // Check if the caller is authorized to edit roles in general
        if (requireEditAccess) {
            assertAuthorizedToEditRoles(authenticationToken);
        } else {
            assertAuthorizedToViewRoles(authenticationToken);
        }
        // Is the authToken authorized to the role found by id in the database?
        final Role roleById = roleId==Role.ROLE_ID_UNASSIGNED ? null : roleDataSession.getRole(roleId);
        if (roleById!=null) {
            final Set<Integer> roleIdsCallerBelongsTo = roleMemberDataSession.getRoleIdsMatchingAuthenticationToken(authenticationToken);
            assertAuthorizedToAllAccessRules(authenticationToken, roleById, roleIdsCallerBelongsTo);
            assertAuthorizedToNameSpace(authenticationToken, roleById, roleIdsCallerBelongsTo);
        }
    }
    
    private Role getOriginalRoleAndAssertAuthorizedToEdit(final AuthenticationToken authenticationToken, final Role role, final boolean requireNonImportantRoleMembership)
            throws AuthorizationDeniedException {
        // Check if the caller is authorized to edit roles in general
        assertAuthorizedToEditRoles(authenticationToken);
        // Is the authToken authorized to the role as provided as an argument?
        final Set<Integer> roleIdsCallerBelongsTo = roleMemberDataSession.getRoleIdsMatchingAuthenticationToken(authenticationToken);
        assertAuthorizedToAllAccessRules(authenticationToken, role, roleIdsCallerBelongsTo);
        if (requireNonImportantRoleMembership) {
            assertNonImportantRoleMembership(authenticationToken, role, roleIdsCallerBelongsTo);
        }
        assertAuthorizedToNameSpace(authenticationToken, role, roleIdsCallerBelongsTo);
        // Is the authToken authorized to the role found by id in the database?
        final Role roleById = role.getRoleId()==Role.ROLE_ID_UNASSIGNED ? null : roleDataSession.getRole(role.getRoleId());
        if (roleById!=null) {
            assertAuthorizedToAllAccessRules(authenticationToken, roleById, roleIdsCallerBelongsTo);
            assertAuthorizedToNameSpace(authenticationToken, roleById, roleIdsCallerBelongsTo);
        }
        return roleById;
    }
    

    @Override
    public Role persistRole(final AuthenticationToken authenticationToken, final Role role) throws RoleExistsException, AuthorizationDeniedException {
        return persistRole(authenticationToken, role, true);
    }
    
    @Override
    public Role persistRole(final AuthenticationToken authenticationToken, final Role role, final boolean requireNonImportantRoleMembership)
            throws RoleExistsException, AuthorizationDeniedException {
        // Normalize and minimize access rules before checking authorization
        role.normalizeAccessRules();
        role.minimizeAccessRules();
        final Role roleById = getOriginalRoleAndAssertAuthorizedToEdit(authenticationToken, role, requireNonImportantRoleMembership);
        // Sort access rules to make raw xml editing (e.g. statedump) easier
        role.sortAccessRules();
        final Role roleByName = roleDataSession.getRole(role.getNameSpace(), role.getRoleName());
        if (roleById == null) {
            if (roleByName!=null) {
                throw new RoleExistsException(InternalResources.getInstance().getLocalizedMessage("authorization.erroraddroleexists", role.getRoleNameFull()));
            }
            // Enforce a non-empty role name
            if (StringUtils.isEmpty(role.getRoleName())) {
                throw new IllegalArgumentException("Role name cannot be empty.");
            }
            // Persist new role
            if (log.isTraceEnabled()) {
                log.trace("Creating new role with data: " + role);
            }
            role.setRoleId(roleDataSession.persistRole(role).getRoleId());
            final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.roleadded", role.getRoleName());
            final Map<String, Object> details = new LinkedHashMap<>();
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
                Map<String, Object> details = new LinkedHashMap<>();
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
            if (log.isTraceEnabled()) {
                log.trace("Updating existing role with new data: " + role);
            }
            roleDataSession.persistRole(role);
        }
        // Audit log access rule changes (also for new roles)
        final HashMap<String, Boolean> newAccessRules = role.getAccessRules();
        final HashMap<String, Boolean> oldAccessRules = roleById==null ? new HashMap<>() : roleById.getAccessRules();
        final Map<Object,Object> oldAuditMap = new HashMap<>();
        for (final Entry<String,Boolean> entry : oldAccessRules.entrySet()) {
            oldAuditMap.put(entry.getKey(), entry.getValue().booleanValue() ? "allow" : "deny");
        }
        final Map<Object,Object> newAuditMap = new HashMap<>();
        for (final Entry<String,Boolean> entry : newAccessRules.entrySet()) {
            newAuditMap.put(entry.getKey(), entry.getValue().booleanValue() ? "allow" : "deny");
        }
        final Map<Object, Object> auditLogDiffMap = UpgradeableDataHashMap.diffMaps(oldAuditMap, newAuditMap);
        if (!auditLogDiffMap.isEmpty()) {
            final StringBuilder rulesMsg = new StringBuilder();
            for (Map.Entry<Object, Object> entry : auditLogDiffMap.entrySet()) {
                rulesMsg.append("[" + entry.getKey().toString() + ":"+entry.getValue().toString()+"]");
            }
            final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.accessruleschanged", role.getRoleNameFull(), rulesMsg.toString());
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            details.put("roleId", role.getRoleId());
            details.put("roleName", role.getRoleName());
            details.put("nameSpace", role.getNameSpace());
            securityEventsLoggerSession.log(EventTypes.ROLE_ACCESS_RULE_CHANGE, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
        return role;
    }

    /**
     * Asserts that authentication token is authorized to edit roles in general. 
     * 
     * @param authenticationToken a token for the authenticating entity
     * @throws AuthorizationDeniedException if not authorized
     */
    private void assertAuthorizedToEditRoles(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.EDITROLES.resource())) {
            String msg = InternalResources.getInstance().getLocalizedMessage("authorization.notauthorizedtoeditroles", authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }
    
    /** Like {@link #assertAuthorizedToEditRoles(AuthenticationToken)}, but check for view access */
    private void assertAuthorizedToViewRoles(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.VIEWROLES.resource())) {
            String msg = InternalResources.getInstance().getLocalizedMessage("authorization.notauthorizedtoviewroles", authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }

    /** @throws AuthorizationDeniedException if the caller is not authorized to one of the rules granted access to (even implied) by this role */
    private void assertAuthorizedToAllAccessRules(final AuthenticationToken authenticationToken, final Role role, final Set<Integer> roleIdsCallerBelongsTo) throws AuthorizationDeniedException {
        if (!isAuthorizedToAllAccessRules(authenticationToken, role, roleIdsCallerBelongsTo)) {
            throw new AuthorizationDeniedException("Not authorized to all access rules in role.");
        }
    }

    /** @throws AuthorizationDeniedException if the caller is not authorized to one of the rules granted access to (even implied) by this role */
    private boolean isAuthorizedToAllAccessRules(final AuthenticationToken authenticationToken, final Role role, final Set<Integer> roleIdsCallerBelongsTo) {
        // Verify that authenticationToken has access to every single added allow access rule
        for (final Entry<String, Boolean> entry : role.getAccessRules().entrySet()) {
            if (entry.getValue().booleanValue()) {
                if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, entry.getKey())) {
                    // Role would allow what is is not granted to current authenticationToken
                    return false;
                }
            }
        }
        // Verify that role does not have access to any rule that is denied to this authenticationToken
        HashMap<String, Boolean> totalAccessRules = new HashMap<>();
        for (final int roleId : roleIdsCallerBelongsTo) {
            totalAccessRules = AccessRulesHelper.getAccessRulesUnion(totalAccessRules, roleDataSession.getRole(roleId).getAccessRules());
        }
        for (final Entry<String, Boolean> entry : totalAccessRules.entrySet()) {
            if (!entry.getValue().booleanValue()) {
                if (role.hasAccessToResource(entry.getKey())) {
                    // Role would allow what is denied to current authenticationToken
                    return false;
                }
            }
        }
        return true;
    }

    /** @throws AuthorizationDeniedException if the nameSpace is not "owned" by the caller. */
    private void assertAuthorizedToNameSpace(final AuthenticationToken authenticationToken, final Role role, final Set<Integer> roleIdsCallerBelongsTo) throws AuthorizationDeniedException {
        // Assert that AuthenticationToken is allowed to mess with the role's nameSpace
        if (!isAuthorizedToNameSpace(authenticationToken, role, roleIdsCallerBelongsTo)) {
            throw new AuthorizationDeniedException("Current AuthenticationToken is not authorized to the namespace '"+role.getNameSpace()+"'.");
        }
    }
    
    /** @return true if the authenticationToken is authorized to all CAs that are issuers of RoleMembers in this Role */
    private boolean isAuthorizedToAllRoleMembersIssuers(final AuthenticationToken authenticationToken, final int roleId) {
        // Verify that the caller is authorized to all CAs that are issuers of members in this role
        final Set<String> tokenIssuerAccessRules = new HashSet<>();
        for (final RoleMemberData roleMemberData : roleMemberDataSession.findByRoleId(roleId)) {
            boolean checkIssuerAccess = true;
            final AuthenticationTokenMetaData metaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(roleMemberData.getTokenType());
            if (metaData != null) {
                final AccessMatchValue matchKey = metaData.getAccessMatchValueIdMap().get(roleMemberData.getTokenMatchKey());
                if (matchKey != null) {
                    checkIssuerAccess = matchKey.isIssuedByCa();
                } else {
                    log.warn("Unsupported match key #" + roleMemberData.getTokenMatchKey() + " for token type " + roleMemberData.getTokenType());
                }
            } else {
                log.warn("Unsupported token type " + roleMemberData.getTokenType());
            }
            if (checkIssuerAccess) {
                tokenIssuerAccessRules.add(StandardRules.CAACCESS.resource() + roleMemberData.getTokenIssuerId());
            }
        }
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, tokenIssuerAccessRules.toArray(new String[tokenIssuerAccessRules.size()]));
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void assertNonImportantRoleMembership(final AuthenticationToken authenticationToken, final int roleId) throws AuthorizationDeniedException {
        final Role role = roleDataSession.getRole(roleId);
        if (role!=null) {
            // Check that authenticationToken is allowed to remove the role with all its rights
            final Set<Integer> roleIdsCallerBelongsTo = roleMemberDataSession.getRoleIdsMatchingAuthenticationToken(authenticationToken);
            assertNonImportantRoleMembership(authenticationToken, role, roleIdsCallerBelongsTo);
        }
    }

    private void assertNonImportantRoleMembership(final AuthenticationToken authenticationToken, final Role role, final Set<Integer> roleIdsCallerBelongsTo) throws AuthorizationDeniedException {
        if (role.getRoleId()!=Role.ROLE_ID_UNASSIGNED) {
            // Check that authenticationToken is not about to lock itself out by modifying its own role
            if (roleIdsCallerBelongsTo.contains(role.getRoleId())) {
                if (log.isDebugEnabled()) {
                    log.debug("'"+authenticationToken+"' relies on match from Role with id " + role.getRoleId() + " for access.");
                }
                // As long as the admin does not lower its own privileges we are ok with
                HashMap<String, Boolean> accessRulesBefore = new HashMap<>();
                HashMap<String, Boolean> accessRulesAfter = new HashMap<>();
                final Set<String> accessToNamespacesBefore = new HashSet<>();
                final Set<String> accessToNamespacesAfter = new HashSet<>();
                for (final int roleId : roleIdsCallerBelongsTo) {
                    final Role existingRole = roleDataSession.getRole(roleId);
                    final HashMap<String, Boolean> accessRulesFromRole = existingRole.getAccessRules();
                    accessRulesBefore = AccessRulesHelper.getAccessRulesUnion(accessRulesBefore, accessRulesFromRole);
                    accessToNamespacesBefore.add(existingRole.getNameSpace());
                    if (roleId!=role.getRoleId()) {
                        accessRulesAfter = AccessRulesHelper.getAccessRulesUnion(accessRulesAfter, accessRulesFromRole);
                        accessToNamespacesAfter.add(existingRole.getNameSpace());
                    } else {
                        accessToNamespacesAfter.add(role.getNameSpace());
                    }
                }
                if (!accessRulesBefore.equals(accessRulesAfter)) {
                    throw new AuthorizationDeniedException("Granted access of the current administrator might be affected by this change.");
                }
                if (!accessToNamespacesBefore.equals(accessToNamespacesAfter) &&
                        !(accessToNamespacesBefore.contains("") && accessToNamespacesAfter.contains(""))) {
                    throw new AuthorizationDeniedException("Granted namespace access of the current administrator would be affected by this change.");
                }
                if (log.isDebugEnabled()) {
                    log.debug("Access granted to '"+authenticationToken+"' would not be affected by not being a member of Role with id " + role.getRoleId() + ".");
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("'"+authenticationToken+"' does not rely on match from Role with id " + role.getRoleId() + ".");
                }
            }
        }
    }
    
    /** @throws AuthorizationDeniedException if the nameSpace is not "owned" by the caller. */
    private boolean isAuthorizedToNameSpace(final AuthenticationToken authenticationToken, final Role role, final Set<Integer> roleIdsCallerBelongsTo) {
        if (authenticationToken instanceof AlwaysAllowLocalAuthenticationToken) {
            return true; // AlwaysAllowLocalAuthenticationToken cannot belong to any roles, so the code below will not work
        }
        // Assert that AuthenticationToken is allowed to mess with the role's nameSpace
        final Set<String> ownedNameSpaces = new HashSet<>();
        for (final int current : roleIdsCallerBelongsTo) {
            ownedNameSpaces.add(roleDataSession.getRole(current).getNameSpace());
        }
        return ownedNameSpaces.contains("") || ownedNameSpaces.contains(role.getNameSpace());
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<String> getAuthorizedNamespaces(final AuthenticationToken authenticationToken) {
        final Set<String> namespaces = new HashSet<>();
        for (final int current : roleMemberDataSession.getRoleIdsMatchingAuthenticationToken(authenticationToken)) {
            namespaces.add(roleDataSession.getRole(current).getNameSpace());
        }
        if (namespaces.contains("") || authenticationToken instanceof AlwaysAllowLocalAuthenticationToken) {
            // Add all namespaces from authorized roles
            for (final Role role : getAuthorizedRoles(authenticationToken)) {
                namespaces.add(role.getNameSpace());
            }
        }
        return new ArrayList<>(namespaces);
    }
    
    @Override
    public boolean updateCaId(final int caIdOld, final int caIdNew, final boolean keepOldAccessRule, final boolean updateRoleMembers) {
        final String resourceOld = AccessRulesHelper.normalizeResource(StandardRules.CAACCESS.resource() + caIdOld);
        final String resourceNew = AccessRulesHelper.normalizeResource(StandardRules.CAACCESS.resource() + caIdNew);
        boolean hasChangedAnything = false;
        for (final Role role : roleDataSession.getAllRoles()) {
            final Boolean state = role.getAccessRules().get(resourceOld);
            if (state!=null) {
                if (!keepOldAccessRule) {
                    role.getAccessRules().remove(resourceOld);
                }
                role.getAccessRules().put(resourceNew, state);
                roleDataSession.persistRole(role);
                hasChangedAnything = true;
            }
            if (updateRoleMembers) {
                for (final RoleMember roleMember : roleMemberDataSession.findRoleMemberByRoleId(role.getRoleId())) {
                    if (roleMember.getTokenIssuerId()==caIdOld) {
                        // Do more expensive checks if it is a potential match
                        final AccessMatchValue accessMatchValue = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(
                                roleMember.getTokenType()).getAccessMatchValueIdMap().get(roleMember.getTokenMatchKey());
                        if (accessMatchValue.isIssuedByCa()) {
                            roleMember.setTokenIssuerId(caIdNew);
                            roleMemberDataSession.persistRoleMember(roleMember);
                            hasChangedAnything = true;
                        }
                    }
                }
            }
        }
        return hasChangedAnything;
    }
}
