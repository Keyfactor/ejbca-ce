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
import java.util.Arrays;
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

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.access.AccessTree;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.util.ProfileID;

/**
 * Implementation of the RoleManagementSession interface.
 * 
 * @version $Id$
 */
@Deprecated
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleManagementSessionBean implements RoleManagementSessionLocal {

    private static final InternalResources INTERNAL_RESOURCES = InternalResources.getInstance();

    @EJB private RoleAccessSessionLocal roleAccessSession;

    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public AdminGroupData create(AuthenticationToken authenticationToken, String roleName) throws RoleExistsException {
        if (roleAccessSession.findRole(roleName) == null) {
            AdminGroupData role = new AdminGroupData(findFreeRoleId(), roleName);
            entityManager.persist(role);
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.roleadded", roleName);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_CREATION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
            return role;
        } else {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.erroraddroleexists", roleName);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_CREATION, EventStatus.FAILURE, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
            throw new RoleExistsException(msg);
        }
    }

    @Override
    public void deleteIfPresentNoAuth(AuthenticationToken authenticationToken, String roleName) {
        final AdminGroupData role = roleAccessSession.findRole(roleName);
        if (role != null) {
            for (AccessUserAspectData userAspect : role.getAccessUsers().values()) {
                entityManager.remove(userAspect);
            }
            removeAccessRuleDatas(role.getAccessRules().values());
            entityManager.remove(role);
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.roleremoved", roleName);
            securityEventsLogger.log(EventTypes.ROLE_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, msg);
        }
    }

    @Override
    public AdminGroupData addAccessRulesToRole(AuthenticationToken authenticationToken, final AdminGroupData role, final Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException {
        AdminGroupData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
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
        logAccessRulesAdded(authenticationToken, role.getRoleName(), rulesAdded);

        return result;
    }

    @Override
    public AdminGroupData removeAccessRulesFromRole(AuthenticationToken authenticationToken, final AdminGroupData role, Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException {
        AdminGroupData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }
        Map<Integer, AccessRuleData> resultAccessRules = result.getAccessRules();
        for (AccessRuleData accessRule : accessRules) {
            if (resultAccessRules.containsKey(accessRule.getPrimaryKey())) {
                removeAccessRuleDatas(Arrays.asList(accessRule));
            }
        }
        result.setAccessRules(resultAccessRules);
        logAccessRulesRemoved(authenticationToken, role.getRoleName(), accessRules);

        return result;
    }

    @Override
    public AdminGroupData addSubjectsToRole(AuthenticationToken authenticationToken, final AdminGroupData role, Collection<AccessUserAspectData> accessUserAspectDatas)
            throws RoleNotFoundException {
        if (roleAccessSession.findRole(role.getPrimaryKey()) == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
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
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_USER_ADDITION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
        if (subjectsChanged.length() > 0) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.adminchanged", subjectsChanged, role.getRoleName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_USER_CHANGE, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
        return result;
    }
    
    /** Finds an AccessUserAspectData by its primary key. A primary key can be generated statically from AccessUserAspectData. */
    private AccessUserAspectData getAccessUserAspectData(final int primaryKey) {
        return entityManager.find(AccessUserAspectData.class, primaryKey);
    }


    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<AdminGroupData> getAllRolesAuthorizedToEdit(AuthenticationToken authenticationToken) {
        List<AdminGroupData> result = new ArrayList<AdminGroupData>();
        for (AdminGroupData role : roleAccessSession.getAllRoles()) {
            result.add(role);
        }
        return result;
    }
        
    @Override
    public List<AdminGroupData> getAuthorizedRoles(String resource, boolean requireRecursive) {
        Collection<AdminGroupData> roles = roleAccessSession.getAllRoles();
        Collection<AdminGroupData> onerole = new ArrayList<AdminGroupData>();
        ArrayList<AdminGroupData> authissueingadmgrps = new ArrayList<AdminGroupData>();
        for (AdminGroupData role : roles) {
            // We want to check all roles if they are authorized, we can do that with a "private" AccessTree.
            // Probably quite inefficient but...
            AccessTree tree = new AccessTree();
            onerole.clear();
            onerole.add(role);
            tree.buildTree(onerole);
            // Create an AlwaysAllowAuthenticationToken just to find out if there is
            // an access rule for the requested resource
            AlwaysAllowLocalAuthenticationToken token = new AlwaysAllowLocalAuthenticationToken("RoleManagementSessionBean.getAuthorizedRoles");
            try {
                if (tree.isAuthorized(token, resource, requireRecursive)) {
                    authissueingadmgrps.add(role);
                }
            } catch (AuthenticationFailedException e) {
                /*
                 * Naturally, this can't ever fail. 
                 */
                // NOPMD
            }
        }
        return authissueingadmgrps;
    }

    private void logAccessRulesRemoved(AuthenticationToken authenticationToken, String rolename, Collection<AccessRuleData> removedRules) {
        if (removedRules.size() > 0) {
            StringBuilder removedRulesMsg = new StringBuilder();
            for(AccessRuleData removedRule : removedRules) {
                removedRulesMsg.append("[" + removedRule.getAccessRuleName() + "]");
            }      
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.accessrulesremoved", rolename, removedRulesMsg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_RULE_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
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

    private Integer findFreeRoleId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return roleAccessSession.findRole(Integer.valueOf(i)) == null;
            }
        };
        return Integer.valueOf(ProfileID.getNotUsedID(db));
    }

    @Deprecated 
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public AdminGroupData replaceAccessRulesInRoleNoAuth(final AuthenticationToken authenticationToken, final AdminGroupData role,
            final Collection<AccessRuleData> accessRules) throws RoleNotFoundException {
        
        AdminGroupData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }

        Map<Integer, AccessRuleData> rulesFromResult = result.getAccessRules();
        Map<Integer, AccessRuleData> rulesToResult = new HashMap<>();
        //Lists for logging purposes.
        Collection<AccessRuleData> newRules = new ArrayList<>();
        Collection<AccessRuleData> changedRules = new ArrayList<>();
        for (AccessRuleData rule : accessRules) {
            if (AccessRuleData.generatePrimaryKey(role.getRoleName(), rule.getAccessRuleName()) != rule.getPrimaryKey()) {
                throw new Error("Role " + role.getRoleName() + " did not match up with the role that created this rule.");
            }
            Integer ruleKey = rule.getPrimaryKey();
            if (rulesFromResult.containsKey(ruleKey)) {
                AccessRuleData oldRule = rulesFromResult.get(ruleKey);
                if(!oldRule.equals(rule)) {
                    changedRules.add(oldRule);
                }
                AccessRuleData newRule = setAccessRuleDataState(rule, rule.getInternalState(), rule.getRecursive());
                rulesFromResult.remove(ruleKey);
                rulesToResult.put(newRule.getPrimaryKey(), newRule);         
            } else {
                rulesToResult.put(rule.getPrimaryKey(), rule);
            }
        }
        logAccessRulesAdded(authenticationToken, role.getRoleName(), newRules);
        logAccessRulesChanged(authenticationToken, role.getRoleName(), changedRules);

        //And for whatever remains:
        removeAccessRuleDatas(rulesFromResult.values());
        result.setAccessRules(rulesToResult);
        result = entityManager.merge(result);
        logAccessRulesRemoved(authenticationToken, role.getRoleName(), rulesFromResult.values());
        return result;
    }
    
    private void logAccessRulesChanged(AuthenticationToken authenticationToken, String rolename, Collection<AccessRuleData> changedRules) {
        if (changedRules.size() > 0) {
            StringBuilder changedRulesMsg = new StringBuilder();
            for(AccessRuleData changedRule : changedRules) {
                changedRulesMsg.append("[" + changedRule.toString() + "]");
            }
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.accessruleschanged", rolename, changedRulesMsg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_RULE_CHANGE, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
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

    private AccessRuleData createAccessRuleData(final String accessRuleName, final String roleName, final AccessRuleState state, boolean isRecursive) {
        AccessRuleData result = null;
        int primaryKey = AccessRuleData.generatePrimaryKey(roleName, accessRuleName);
        if (entityManager.find(AccessRuleData.class, primaryKey) == null) {
            result = new AccessRuleData(primaryKey, accessRuleName, state, isRecursive);
            entityManager.persist(result);
        }
        return result;
    }
}
