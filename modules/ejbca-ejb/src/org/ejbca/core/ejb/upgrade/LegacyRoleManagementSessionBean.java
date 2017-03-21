/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.upgrade;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.util.ProfileID;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSession;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.SecConst;

/**
 * Implementation of the legacy role management needed by upgrade.
 * 
 * @deprecated since EJBCA 6.8.0
 * @version $Id$
 */
@Deprecated
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class LegacyRoleManagementSessionBean implements LegacyRoleManagementSessionLocal {

    private static final Logger log = Logger.getLogger(LegacyRoleManagementSessionBean.class);
    private static final InternalResources INTERNAL_RESOURCES = InternalResources.getInstance();

    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public AdminGroupData create(AuthenticationToken authenticationToken, String roleName) throws RoleExistsException {
        if (getRole(roleName) == null) {
            AdminGroupData role = new AdminGroupData(findFreeRoleId(), roleName);
            entityManager.persist(role);
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.roleadded", roleName);
            securityEventsLogger.log(EventTypes.ROLE_CREATION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, msg);
            return role;
        } else {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.erroraddroleexists", roleName);
            securityEventsLogger.log(EventTypes.ROLE_CREATION, EventStatus.FAILURE, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, msg);
            throw new RoleExistsException(msg);
        }
    }

    private Integer findFreeRoleId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return entityManager.find(AdminGroupData.class, i)==null;
            }
        };
        return Integer.valueOf(ProfileID.getNotUsedID(db));
    }

    @Override
    public void addAccessRuleDataToRolesWhenAccessIsImplied(final AuthenticationToken authenticationToken, final String skipWhenRecursiveAccessTo,
            final List<String> requiredAccessRules, final List<String> grantedAccessRules, final boolean grantedAccessRecursive) {
        for (final AdminGroupData role : getAllRoles()) {
            if (role.hasAccessToRule(skipWhenRecursiveAccessTo, true)) {
                // No need to grant extra privileges to if the specified recursive access is granted to the current role
                continue;
            }
            boolean allGranted = true;
            for (final String requiredAccess : requiredAccessRules) {
                // If a rule will be granted, we don't require access to it just as the legacy code
                if (!grantedAccessRules.contains(requiredAccess) && !role.hasAccessToRule(requiredAccess)) {
                    allGranted = false;
                    break;
                }
            }
            if (allGranted) {
                final List<AccessRuleData> accessRuleDatas = new ArrayList<>();
                for (final String grantedResource : grantedAccessRules) {
                    accessRuleDatas.add(new AccessRuleData(role.getRoleName(), grantedResource, AccessRuleState.RULE_ACCEPT, grantedAccessRecursive));
                }
                addAccessRulesToRole(authenticationToken, role, accessRuleDatas);
            }
        }
    }

    @Override
    public AdminGroupData addAccessRulesToRole(AuthenticationToken authenticationToken, final AdminGroupData adminGroupData, final Collection<AccessRuleData> accessRules) {
        AdminGroupData result;
        if (!entityManager.contains(adminGroupData)) {
            result = entityManager.find(AdminGroupData.class, adminGroupData.getPrimaryKey());
        } else {
            result = adminGroupData;
        }
        Map<Integer, AccessRuleData> rules = result.getAccessRules();
        Collection<AccessRuleData> rulesAdded = new ArrayList<AccessRuleData>();
        Collection<AccessRuleData> rulesMerged = new ArrayList<AccessRuleData>();
        for (AccessRuleData accessRule : accessRules) {
            // If this rule isn't persisted, persist it.
            if (entityManager.find(AccessRuleData.class, accessRule.getPrimaryKey()) == null) {
                entityManager.persist(accessRule);
                rulesAdded.add(accessRule);
            }
            // If the rule exists, then merely update its values.
            if (rules.containsKey(accessRule.getPrimaryKey())) {
                rules.remove(accessRule.getPrimaryKey());
                accessRule = setAccessRuleDataState(accessRule, accessRule.getInternalState(), accessRule.getRecursive());
                rulesMerged.add(accessRule);
            }
            rules.put(accessRule.getPrimaryKey(), accessRule);
        }
        result.setAccessRules(rules);
        result = entityManager.merge(result);
        logAccessRulesAdded(authenticationToken, adminGroupData.getRoleName(), rulesAdded);
        return result;
    }

    @Override
    public AdminGroupData addSubjectsToRole(AuthenticationToken authenticationToken, final AdminGroupData adminGroupData, Collection<AccessUserAspectData> accessUserAspectDatas) {
        final AdminGroupData role;
        if (!entityManager.contains(adminGroupData)) {
            role = entityManager.find(AdminGroupData.class, adminGroupData.getPrimaryKey());
        } else {
            role = adminGroupData;
        }
        Map<Integer, AccessUserAspectData> existingUsers = role.getAccessUsers();
        final StringBuilder subjectsAdded = new StringBuilder();
        final StringBuilder subjectsChanged = new StringBuilder();
        for (AccessUserAspectData accessUserAspectData : accessUserAspectDatas) {
            AccessUserAspectData legacyVersion = getAccessUserAspectData(accessUserAspectData.getLegacyPrimaryKey());
            if (legacyVersion != null) {
                //If an aspect exists using the old primary key, remove it so that we can replace it with the new one.
                entityManager.remove(legacyVersion);
            }
            if (getAccessUserAspectData(accessUserAspectData.getPrimaryKey()) == null) {
                // if userAspect hasn't been persisted, do so.
                entityManager.persist(accessUserAspectData);
            }
            if (existingUsers.containsKey(accessUserAspectData.getPrimaryKey())) {
                existingUsers.remove(accessUserAspectData.getPrimaryKey());
                subjectsChanged.append("[" + accessUserAspectData.toString() + "]");
            } else {
                subjectsAdded.append("[" + accessUserAspectData.toString() + "]");
            }
            existingUsers.put(accessUserAspectData.getPrimaryKey(), accessUserAspectData);
        }
        role.setAccessUsers(existingUsers);
        AdminGroupData result = entityManager.merge(role);
        if (subjectsAdded.length() > 0) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.adminadded", subjectsAdded, role.getRoleName());
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_USER_ADDITION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, msg);
        }
        if (subjectsChanged.length() > 0) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.adminchanged", subjectsChanged, role.getRoleName());
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_USER_CHANGE, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, msg);
        }
        return result;
    }
    
    /** Finds an AccessUserAspectData by its primary key. A primary key can be generated statically from AccessUserAspectData. */
    private AccessUserAspectData getAccessUserAspectData(final int primaryKey) {
        return entityManager.find(AccessUserAspectData.class, primaryKey);
    }

    private void logAccessRulesAdded(AuthenticationToken authenticationToken, String rolename, Collection<AccessRuleData> addedRules) {
        if (addedRules.size() > 0) {
            StringBuilder addedRulesMsg = new StringBuilder();
            for(AccessRuleData addedRule : addedRules) {
                addedRulesMsg.append("[" + addedRule.toString() + "]");
            }            
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.accessrulesadded", rolename, addedRulesMsg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_RULE_ADDITION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
    }

    private void removeAccessRuleDatas(Collection<AccessRuleData> accessRules) {
        for (final AccessRuleData accessRule : accessRules) {
            entityManager.remove(getAccessRuleDataManaged(accessRule));
        }
    }

    private AccessRuleData getAccessRuleDataManaged(final AccessRuleData accessRuleData) {
        if (entityManager.contains(accessRuleData)) {
            // If this was already managed, assume that rowVersion is proper
            return accessRuleData;
        }
        return entityManager.find(AccessRuleData.class, accessRuleData.getPrimaryKey());
    }

    private AccessRuleData setAccessRuleDataState(final AccessRuleData rule, final AccessRuleState state, boolean isRecursive) {
        AccessRuleData result = getAccessRuleDataManaged(rule);
        result.setInternalState(state);
        result.setRecursive(isRecursive);
        return result;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<AdminGroupData> getAllRoles() {
        final List<AdminGroupData> allRoles = entityManager.createQuery("SELECT a FROM AdminGroupData a", AdminGroupData.class).getResultList();
        return allRoles != null ? allRoles : new ArrayList<AdminGroupData>();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AdminGroupData getRole(final String roleName) {
        final TypedQuery<AdminGroupData> query = entityManager.createQuery("SELECT a FROM AdminGroupData a WHERE a.roleName=:roleName", AdminGroupData.class);
        query.setParameter("roleName", roleName);
        return QueryResultWrapper.getSingleResult(query);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void createSuperAdministrator() {
        final String TEMPORARY_SUPERADMIN_ROLE = "Temporary Super Administrator Group";
        final String SUPERADMIN_ROLE = AuthorizationSystemSession.SUPERADMIN_ROLE;
        // Create the Super Admin
        AdminGroupData role = getRole(SUPERADMIN_ROLE);
        if (role == null) {
            log.debug("Creating new role '" + SUPERADMIN_ROLE + "'.");
            role = new AdminGroupData(1, SUPERADMIN_ROLE);
            entityManager.persist(role);
        } else {
            log.debug("'" + SUPERADMIN_ROLE + "' already exists, not creating new.");            
        }
        AccessRuleData rule = new AccessRuleData(SUPERADMIN_ROLE, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true);
        if (!role.getAccessRules().containsKey(rule.getPrimaryKey())) {
            log.debug("Adding new rule '/' to " + SUPERADMIN_ROLE + ".");
            Map<Integer, AccessRuleData> newrules = new HashMap<>();
            newrules.put(rule.getPrimaryKey(), rule);
            role.setAccessRules(newrules);
        } else {
            log.debug("rule '/' already exists in " + SUPERADMIN_ROLE + ".");
        }
        // Pick up the aspects from the old temp. super admin group and add them to the new one.
        Map<Integer, AccessUserAspectData> newUsers = new HashMap<>();
        AdminGroupData oldSuperAdminRole = getRole(TEMPORARY_SUPERADMIN_ROLE);
        if (oldSuperAdminRole != null) {
            Map<Integer, AccessUserAspectData> oldSuperAdminAspects = oldSuperAdminRole.getAccessUsers();
            Map<Integer, AccessUserAspectData> existingSuperAdminAspects = role.getAccessUsers();
            for (AccessUserAspectData aspect : oldSuperAdminAspects.values()) {
                AccessMatchValue matchWith = AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(
                        X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, aspect.getMatchWith());
                AccessUserAspectData superAdminUserAspect = new AccessUserAspectData(SUPERADMIN_ROLE, aspect.getCaId(), matchWith,
                        aspect.getMatchTypeAsType(), aspect.getMatchValue());
                if (existingSuperAdminAspects.containsKey(superAdminUserAspect.getPrimaryKey())) {
                    log.debug(SUPERADMIN_ROLE + " already contains aspect matching " + aspect.getMatchValue() + " for CA with ID " + aspect.getCaId());
                } else {
                    newUsers.put(superAdminUserAspect.getPrimaryKey(), superAdminUserAspect);
                }
            }
        }
        // Create the CLI Default User
        Map<Integer, AccessUserAspectData> users = role.getAccessUsers();
        AccessUserAspectData defaultCliUserAspect = new AccessUserAspectData(SUPERADMIN_ROLE, 0, CliUserAccessMatchValue.USERNAME,
                AccessMatchType.TYPE_EQUALCASE, EjbcaConfiguration.getCliDefaultUser());
        if (!users.containsKey(defaultCliUserAspect.getPrimaryKey())) {
            log.debug("Adding new AccessUserAspect '"+EjbcaConfiguration.getCliDefaultUser()+"' to " + SUPERADMIN_ROLE + ".");
            newUsers.put(defaultCliUserAspect.getPrimaryKey(), defaultCliUserAspect);
            UserData defaultCliUserData = new UserData(EjbcaConfiguration.getCliDefaultUser(), EjbcaConfiguration.getCliDefaultPassword(), false, "UID="
                    + EjbcaConfiguration.getCliDefaultUser(), 0, null, null, null, 0, SecConst.EMPTY_ENDENTITYPROFILE, 0, 0, 0, null);
            defaultCliUserData.setStatus(EndEntityConstants.STATUS_GENERATED);
            if (entityManager.find(UserData.class, defaultCliUserData.getUsername())==null) {
                entityManager.persist(defaultCliUserData);
            }
        } else {
            log.debug("AccessUserAspect '"+EjbcaConfiguration.getCliDefaultUser()+"' already exists in " + SUPERADMIN_ROLE + ".");            
        }
        // Add all created aspects to role
        role.setAccessUsers(newUsers);
    }

    @Override
    public void setTokenTypeWhenNull(final AuthenticationToken authenticationToken) {
        for (final AdminGroupData role : getAllRoles()) {
            final Collection<AccessUserAspectData> updatedUsers = new ArrayList<>();
            for (AccessUserAspectData userAspect : role.getAccessUsers().values()) {
                if (userAspect.getTokenType() == null) {
                    userAspect.setTokenType(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE);
                    updatedUsers.add(userAspect);
                }
            }
            addSubjectsToRole(authenticationToken, role, updatedUsers);
        }
    }

    @Override
    public void deleteRole(AuthenticationToken authenticationToken, String roleName) {
        final AdminGroupData role = getRole(roleName);
        if (role != null) {
            deleteRole(authenticationToken, role);
        }
    }

    @Override
    public void deleteAllRoles(final AuthenticationToken authenticationToken) {
        for (final AdminGroupData role : getAllRoles()) {
            deleteRole(authenticationToken, role);
        }
    }

    private void deleteRole(final AuthenticationToken authenticationToken, final AdminGroupData role) {
        for (AccessUserAspectData userAspect : role.getAccessUsers().values()) {
            entityManager.remove(userAspect);
        }
        removeAccessRuleDatas(role.getAccessRules().values());
        entityManager.remove(role);
        final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.roleremoved", role.getRoleName());
        securityEventsLogger.log(EventTypes.ROLE_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                authenticationToken.toString(), null, null, null, msg);
    }
}
