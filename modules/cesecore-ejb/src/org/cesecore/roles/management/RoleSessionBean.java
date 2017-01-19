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
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.util.ProfileID;
import org.cesecore.util.QueryResultWrapper;

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
    private AccessControlSessionLocal accessControlSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<Role> getAllRoles() {
        final TypedQuery<RoleData> query = entityManager.createQuery("SELECT a FROM RoleData a", RoleData.class);
        final List<Role> ret = new ArrayList<>();
        for (final RoleData roleData : query.getResultList()) {
            ret.add(roleData.getRole());
        }
        return ret;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final AuthenticationToken authenticationToken, final String nameSpace, final String roleName) throws AuthorizationDeniedException {
        final Role role = getRole(nameSpace, roleName);
        if (role!=null) {
            assertAuthorizedToAllAccessRules(authenticationToken, role); // Leaks existence of roleId
        }
        return role;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final String nameSpace, final String roleName) {
        final Integer roleId = RoleCache.INSTANCE.getNameToIdMap().get(Role.getRoleNameFullAsCacheName(nameSpace, roleName));
        if (roleId != null) {
            return getRole(roleId.intValue());
        }
        final RoleData result = getRoleData(nameSpace, roleName);
        final Role role = result==null ? null : result.getRole();
        if (role!=null) {
            RoleCache.INSTANCE.updateWith(role.getRoleId(), role.hashCode(), Role.getRoleNameFullAsCacheName(role.getNameSpace(), role.getRoleName()), role);
        }
        return role;
    }

    private RoleData getRoleData(final String nameSpace, final String roleName) {
        if (StringUtils.isEmpty(nameSpace)) {
            final Query query = entityManager.createQuery("SELECT a FROM RoleData a WHERE a.roleName=:roleName AND a.nameSpace IS NULL");
            query.setParameter("roleName", roleName);
            return QueryResultWrapper.getSingleResult(query);
        } else {
            final Query query = entityManager.createQuery("SELECT a FROM RoleData a WHERE a.roleName=:roleName AND a.nameSpace=:nameSpace");
            query.setParameter("roleName", roleName);
            query.setParameter("nameSpace", nameSpace);
            return QueryResultWrapper.getSingleResult(query);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final AuthenticationToken authenticationToken, final int roleId) throws AuthorizationDeniedException {
        final Role role = getRole(roleId);
        if (role!=null) {
            assertAuthorizedToAllAccessRules(authenticationToken, role); // Leaks existence of roleId
        }
        return role;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Role getRole(final int roleId) {
        // 1. Check cache if it is time to sync-up with database
        if (RoleCache.INSTANCE.shouldCheckForUpdates(roleId)) {
            if (log.isDebugEnabled()) {
                log.debug("Object with ID " + roleId + " will be checked for updates.");
            }
            // 2. If cache is expired or missing, first thread to discover this reloads item from database and sends it to the cache
            final RoleData roleData = getRoleData(roleId);
            if (roleData==null) {
                if (log.isDebugEnabled()) {
                    log.debug("Requested object did not exist in database and will be purged from cache if present: " + roleId);
                }
                // Ensure that it is removed from cache when the object is no longer present in the database
                RoleCache.INSTANCE.removeEntry(roleId);
            } else {
                final Role role = roleData==null ? null : roleData.getRole();
                final int digest = role.hashCode();
                // 3. The cache compares the database data with what is in the cache
                // 4. If database is different from cache, replace it in the cache
                RoleCache.INSTANCE.updateWith(roleId, digest, Role.getRoleNameFullAsCacheName(role.getNameSpace(), role.getRoleName()), role);
            }
        }
        // 5. Get object from cache now (or null) and be merry
        return RoleCache.INSTANCE.getEntry(roleId);
    }

    private RoleData getRoleData(final int roleId) {
        final TypedQuery<RoleData> query = entityManager.createQuery("SELECT a FROM RoleData a WHERE a.id=:id", RoleData.class);
        query.setParameter("id", roleId);
        return QueryResultWrapper.getSingleResult(query);
    }

    @Override
    public void deleteRole(final AuthenticationToken authenticationToken, final int roleId) throws RoleNotFoundException, AuthorizationDeniedException {
        assertAuthorizedToEditRoles(authenticationToken);
        final RoleData roleData = getRoleData(roleId);
        if (roleData==null) {
            final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.errorrolenotexists", "id="+roleId);
            throw new RoleNotFoundException(msg);
        }
        final Role role = roleData.getRole();
        // Check that authenticationToken is allowed to remove the role with all its rights
        assertAuthorizedToAllAccessRules(authenticationToken, role);
        assertNotMemberAndAuthorizedToNameSpace(authenticationToken, role);
        deleteRoleNoAuthorizationCheck(roleId);
        RoleCache.INSTANCE.updateWith(roleId, 0, null, null);
        final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.roleremoved", role.getRoleNameFull());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        details.put("roleId", role.getRoleId());
        details.put("roleName", role.getRoleName());
        details.put("nameSpace", role.getNameSpace());
        securityEventsLoggerSession.log(EventTypes.ROLE_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                authenticationToken.toString(), null, null, null, details);
    }

    @Override
    public boolean deleteRoleNoAuthorizationCheck(final int roleId) {
        // Use an DELETE query instead of entityManager.remove to tolerate concurrent deletion better
        final Query query = entityManager.createQuery("DELETE FROM RoleData a WHERE a.id=:id");
        query.setParameter("id", roleId);
        return query.executeUpdate()==1;

    }
    
    @Override
    public Role persistRole(final AuthenticationToken authenticationToken, final Role role) throws RoleExistsException, AuthorizationDeniedException {
        // Normalize and minimize access rules before checking authorization
        role.normalizeAccessRules();
        role.minimizeAccessRules();
        // Check if the caller is authorized to edit roles in general
        assertAuthorizedToEditRoles(authenticationToken);
        // Is the authToken authorized to the role found by id in the database?
        final RoleData roleDataById = role.getRoleId()==Role.ROLE_ID_UNASSIGNED ? null : getRoleData(role.getRoleId());
        if (roleDataById!=null) {
            assertAuthorizedToAllAccessRules(authenticationToken, roleDataById.getRole());
        }
        // Is the authToken authorized to the role as provided as an argument?
        assertAuthorizedToAllAccessRules(authenticationToken, role);
        assertNotMemberAndAuthorizedToNameSpace(authenticationToken, role);
        persistRoleInternal(authenticationToken, role, roleDataById);
        return role;
    }

    @Override
    public Role persistRoleNoAuthorizationCheck(final AuthenticationToken authenticationToken, final Role role) throws RoleExistsException {
        // Normalize and minimize access rules
        role.normalizeAccessRules();
        role.minimizeAccessRules();
        final RoleData roleDataById = role.getRoleId()==Role.ROLE_ID_UNASSIGNED ? null : getRoleData(role.getRoleId());
        persistRoleInternal(authenticationToken, role, roleDataById);
        return role;
    }

    private void persistRoleInternal(final AuthenticationToken authenticationToken, final Role role, final RoleData roleDataById) throws RoleExistsException {
        if (role.getRoleId()==Role.ROLE_ID_UNASSIGNED) {
            role.setRoleId(findFreeRoleId());
        }
        // Sort access rules to make raw xml editing (e.g. statedump) easier
        role.sortAccessRules();
        final RoleData roleByName = getRoleData(role.getNameSpace(), role.getRoleName());
        if (roleDataById == null) {
            // Persist new role
            if (roleByName!=null) {
                final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.erroraddroleexists", role.getRoleNameFull());
                throw new RoleExistsException(msg);
            }
            entityManager.persist(new RoleData(role));
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
                // Rename role
                final String msg = InternalResources.getInstance().getLocalizedMessage("authorization.rolerenamed", roleDataById.getRole().getRoleNameFull(),
                        role.getRoleNameFull());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("roleId", role.getRoleId());
                details.put("roleNameOld", roleDataById.getRoleName());
                details.put("roleNameNew", role.getRoleName());
                details.put("nameSpaceOld", roleDataById.getNameSpace());
                details.put("nameSpaceNew", role.getNameSpace());
                securityEventsLoggerSession.log(EventTypes.ROLE_RENAMING, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                        authenticationToken.toString(), null, null, null, details);
            } else {
                if (roleByName.getId() != role.getRoleId()) {
                    throw new RoleExistsException("A role with the same name exists.");
                }
            }
            // Persist data changes
            roleDataById.setRole(role);
            //entityManager.merge(roleById); Not needed since the roleById is a managed JPA entity
        }
        // Audit log rule changes (also for new roles)
        final HashMap<String, Boolean> newAccessRules = role.getAccessRules();
        final HashMap<String, Boolean> oldAccessRules = roleDataById==null ? new HashMap<String, Boolean>() : roleDataById.getRole().getAccessRules();
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
        RoleCache.INSTANCE.updateWith(role.getRoleId(), role.hashCode(), Role.getRoleNameFullAsCacheName(role.getNameSpace(), role.getRoleName()), role);
    }

    /** @return a integer Id that is currently unused in the database */
    private int findFreeRoleId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(final int candidate) {
                return candidate!=Role.ROLE_ID_UNASSIGNED && getRole(candidate) == null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    /**
     * Asserts that authentication token is authorized to edit roles in general. 
     * 
     * @param authenticationToken a token for the authenticating entity
     * @throws AuthorizationDeniedException if not authorized
     */
    private void assertAuthorizedToEditRoles(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
        if (!accessControlSession.isAuthorized(authenticationToken, StandardRules.EDITROLES.resource())) {
            String msg = InternalResources.getInstance().getLocalizedMessage("authorization.notauthorizedtoeditroles", authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }

    /** @throws AuthorizationDeniedException if the caller is not authorized to one of the rules granted access to (even implied) by this role */
    private void assertAuthorizedToAllAccessRules(final AuthenticationToken authenticationToken, final Role role) throws AuthorizationDeniedException {
        // Verify that authenticationToken has access to every single added allow access rule
        for (final Entry<String, Boolean> entry : role.getAccessRules().entrySet()) {
            if (entry.getValue().booleanValue()) {
                if (!accessControlSession.isAuthorized(authenticationToken, entry.getKey())) {
                    // Role would allow what is is not granted to current authenticationToken
                    throw new AuthorizationDeniedException("Not authorized to all access rules in role.");
                }
            }
        }
        // Verify that role does not have access to any rule that is denied to this authenticationToken
        final List<Integer> roleIdsCallerBelongsTo = new ArrayList<>(); // TODO: roleMemberSession.getRoleIds(authenticationToken)
        HashMap<String, Boolean> totalAccessRules = new HashMap<>();
        for (final int roleId : roleIdsCallerBelongsTo) {
            totalAccessRules = AccessRulesHelper.mergeTotalAccess(totalAccessRules, getRole(roleId).getAccessRules());
        }
        for (final Entry<String, Boolean> entry : totalAccessRules.entrySet()) {
            if (!entry.getValue().booleanValue()) {
                if (role.hasAccessToResource(entry.getKey())) {
                    // Role would allow what is denied to current authenticationToken
                    throw new AuthorizationDeniedException("Not authorized to all access rules in role.");
                }
            }
        }
    }
    
    /** @throws AuthorizationDeniedException if the caller part of this role (to prevent suicide) or if the nameSpace is not "owned" by the caller. */
    private void assertNotMemberAndAuthorizedToNameSpace(final AuthenticationToken authenticationToken, final Role role) throws AuthorizationDeniedException {
        final int roleId = role.getRoleId();
        final List<Integer> roleIdsCallerBelongsTo = new ArrayList<>(); // TODO: roleMemberSession.getRoleIds(authenticationToken)
        if (roleId!=Role.ROLE_ID_UNASSIGNED) {
            // Check that authenticationToken is not about to lock itself out by modifying its own role
            if (roleIdsCallerBelongsTo.contains(role.getRoleId())) {
                throw new AuthorizationDeniedException("Current AuthenticationToken belongs to this role.");
            }
        }
        // Assert that AuthenticationToken is allowed to mess with the role's nameSpace
        final Set<String> ownedNameSpaces = new HashSet<>();
        for (final int current : roleIdsCallerBelongsTo) {
            ownedNameSpaces.add(getRole(current).getNameSpace());
        }
        if (!ownedNameSpaces.contains("") && !ownedNameSpaces.contains(role.getNameSpace())) {
            // TODO: Remove this log line and re-enable throw statement once auth tokens belong to roles
            log.info("TODO: Would have thrown AuthorizationDeniedException here, but no role is yet in a namespace which would block all tests.");
            //throw new AuthorizationDeniedException("Current AuthenticationToken is not authorized to the namespace '"+role.getNameSpace()+"'.");
        }
    }
}
