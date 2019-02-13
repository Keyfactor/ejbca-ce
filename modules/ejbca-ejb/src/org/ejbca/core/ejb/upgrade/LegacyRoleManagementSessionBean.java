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
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.util.ProfileID;
import org.cesecore.util.QueryResultWrapper;

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
            if (role.hasAccessToRule(skipWhenRecursiveAccessTo, true, getAccessRules(role.getPrimaryKey()))) {
                // No need to grant extra privileges to if the specified recursive access is granted to the current role
                continue;
            }
            boolean allGranted = true;
            for (final String requiredAccess : requiredAccessRules) {
                // If a rule will be granted, we don't require access to it just as the legacy code
                if (!grantedAccessRules.contains(requiredAccess) && !role.hasAccessToRule(requiredAccess, false, getAccessRules(role.getPrimaryKey()))) {
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
        final List<AccessRuleData> accessRuleDatas = getAccessRules(adminGroupData.getPrimaryKey());
        final Collection<AccessRuleData> rulesAdded = new ArrayList<AccessRuleData>();
        final Collection<AccessRuleData> rulesMerged = new ArrayList<AccessRuleData>();
        for (final AccessRuleData accessRule : accessRules) {
            boolean found = false;
            for (final AccessRuleData accessRuleData : accessRuleDatas) {
                if (accessRuleData.getPrimaryKey()==accessRule.getPrimaryKey()) {
                    found = true;
                    accessRuleData.setInternalState(accessRule.getInternalState());
                    accessRuleData.setRecursive(accessRule.getRecursive());
                    rulesMerged.add(accessRuleData);
                    break;
                }
            }
            if (!found) {
                accessRule.setAdminGroupDataPrimaryKey(adminGroupData.getPrimaryKey());
                entityManager.persist(accessRule);
                rulesAdded.add(accessRule);
            }
        }
        logAccessRulesAdded(authenticationToken, adminGroupData.getRoleName(), rulesAdded);
        return adminGroupData;
    }

    @Override
    public AdminGroupData addSubjectsToRole(AuthenticationToken authenticationToken, final AdminGroupData adminGroupData, Collection<AccessUserAspectData> accessUserAspectDatas) {
        final List<AccessUserAspectData> adminEntityDatas = getAccessUsers(adminGroupData.getPrimaryKey());
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
                accessUserAspectData.setAdminGroupDataPrimaryKey(adminGroupData.getPrimaryKey());
                entityManager.persist(accessUserAspectData);
            }
            for (AccessUserAspectData adminEntityData : adminEntityDatas) {
                if (adminEntityData.getPrimaryKey()==accessUserAspectData.getPrimaryKey()) {
                    subjectsChanged.append("[" + accessUserAspectData.toString() + "]");
                    break;
                } else {
                    accessUserAspectData.setAdminGroupDataPrimaryKey(adminGroupData.getPrimaryKey());
                    entityManager.persist(accessUserAspectData);
                    subjectsAdded.append("[" + accessUserAspectData.toString() + "]");
                }
            }
        }
        if (subjectsAdded.length() > 0) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.adminadded", subjectsAdded, adminGroupData.getRoleName());
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_USER_ADDITION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, msg);
        }
        if (subjectsChanged.length() > 0) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.adminchanged", subjectsChanged, adminGroupData.getRoleName());
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_USER_CHANGE, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, msg);
        }
        return adminGroupData;
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
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_RULE_ADDITION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, msg);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<AdminGroupData> getAllRoles() {
        final List<AdminGroupData> allRoles = entityManager.createQuery("SELECT a FROM AdminGroupData a", AdminGroupData.class).getResultList();
        return allRoles != null ? allRoles : new ArrayList<>();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AdminGroupData getRole(final String roleName) {
        final TypedQuery<AdminGroupData> query = entityManager.createQuery("SELECT a FROM AdminGroupData a WHERE a.roleName=:roleName", AdminGroupData.class);
        query.setParameter("roleName", roleName);
        return QueryResultWrapper.getSingleResult(query);
    }

    @Override
    public void setTokenTypeWhenNull(final AuthenticationToken authenticationToken) {
        final Query query = entityManager.createQuery("UPDATE AccessUserAspectData a SET a.tokenType=:tokenType WHERE a.tokenType IS NULL");
        query.setParameter("tokenType", X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE);
        query.executeUpdate();
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
        final Query queryAdminEntityData = entityManager.createQuery("DELETE FROM AccessUserAspectData a WHERE a.adminGroupDataPrimaryKey=:adminGroupDataPrimaryKey");
        queryAdminEntityData.setParameter("adminGroupDataPrimaryKey", role.getPrimaryKey());
        queryAdminEntityData.executeUpdate();
        final Query queryAccessRuleData = entityManager.createQuery("DELETE FROM AccessRuleData a WHERE a.adminGroupDataPrimaryKey=:adminGroupDataPrimaryKey");
        queryAccessRuleData.setParameter("adminGroupDataPrimaryKey", role.getPrimaryKey());
        queryAccessRuleData.executeUpdate();
        entityManager.remove(role);
        final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.roleremoved", role.getRoleName());
        securityEventsLogger.log(EventTypes.ROLE_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                authenticationToken.toString(), null, null, null, msg);
    }
    
    @Override
    public List<AccessUserAspectData> getAccessUsers(final int adminGroupDataPrimaryKey) {
        final TypedQuery<AccessUserAspectData> query = entityManager.createQuery(
                "SELECT a FROM AccessUserAspectData a WHERE a.adminGroupDataPrimaryKey=:adminGroupDataPrimaryKey", AccessUserAspectData.class);
        query.setParameter("adminGroupDataPrimaryKey", adminGroupDataPrimaryKey);
        return query.getResultList();
    }

    @Override
    public List<AccessRuleData> getAccessRules(final int adminGroupDataPrimaryKey) {
        final TypedQuery<AccessRuleData> query = entityManager.createQuery(
                "SELECT a FROM AccessRuleData a WHERE a.adminGroupDataPrimaryKey=:adminGroupDataPrimaryKey", AccessRuleData.class);
        query.setParameter("adminGroupDataPrimaryKey", adminGroupDataPrimaryKey);
        return query.getResultList();
    }
}
