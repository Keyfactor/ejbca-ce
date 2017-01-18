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
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessTree;
import org.cesecore.authorization.access.AccessTreeState;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleExistsException;
import org.cesecore.authorization.rules.AccessRuleManagementSessionLocal;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.AccessUserAspectExistsException;
import org.cesecore.authorization.user.AccessUserAspectManagerSessionLocal;
import org.cesecore.authorization.user.AccessUserAspectNotFoundException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.util.ProfileID;

/**
 * Implementation of the RoleManagementSession interface.
 * 
 * @version $Id$
 * 
 */
@Deprecated
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleManagementSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleManagementSessionBean implements RoleManagementSessionLocal, RoleManagementSessionRemote {

    /** Log4j instance */
    private static final Logger log = Logger.getLogger(RoleManagementSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources INTERNAL_RESOURCES = InternalResources.getInstance();

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @EJB
    private AccessControlSessionLocal accessControlSession;

    @EJB
    private AccessUserAspectManagerSessionLocal accessUserAspectSession;

    @EJB
    private AccessRuleManagementSessionLocal accessRuleManagement;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private RoleAccessSessionLocal roleAccessSession;

    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public AdminGroupData create(AuthenticationToken authenticationToken, String roleName) throws RoleExistsException, AuthorizationDeniedException {
        assertAuthorizedToEditRoles(authenticationToken);
        return createNoAuth(authenticationToken, roleName);
    }

    private AdminGroupData createNoAuth(AuthenticationToken authenticationToken, String roleName) throws RoleExistsException {
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
    public void remove(AuthenticationToken authenticationToken, String roleName) throws RoleNotFoundException, AuthorizationDeniedException {
        final AdminGroupData role = roleAccessSession.findRole(roleName);
        if (role == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", roleName);
            throw new RoleNotFoundException(msg);
        } else {
            remove(authenticationToken, role);
        }
    }

    @Override
    public void remove(AuthenticationToken authenticationToken, AdminGroupData role) throws RoleNotFoundException, AuthorizationDeniedException {
        assertAuthorizedToEditRole(authenticationToken, role);
        removeNoAuth(authenticationToken, role);
    }

    private void removeNoAuth(AuthenticationToken authenticationToken, AdminGroupData role) throws RoleNotFoundException {
        if (role != null) {
            String roleName = role.getRoleName();
            role = roleAccessSession.findRole(role.getPrimaryKey());
            if (role != null) {
                accessUserAspectSession.remove(role.getAccessUsers().values());
                accessRuleManagement.remove(role.getAccessRules().values());

                entityManager.remove(role);
                accessTreeUpdateSession.signalForAccessTreeUpdate();
                accessControlSession.forceCacheExpire();

                final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.roleremoved", roleName);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                securityEventsLogger.log(EventTypes.ROLE_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                        authenticationToken.toString(), null, null, null, details);
            } else {
                if (role == null) {
                    final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", roleName);
                    throw new RoleNotFoundException(msg);
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("trying to remove role by 'null' RoleData.");
            }
        }
    }

    @Override
    public AdminGroupData renameRole(AuthenticationToken authenticationToken, String role, String newName) throws RoleExistsException,
            AuthorizationDeniedException {
        return renameRole(authenticationToken, roleAccessSession.findRole(role), newName);
    }

    @Override
    public AdminGroupData renameRole(AuthenticationToken authenticationToken, AdminGroupData role, String newName) throws RoleExistsException,
            AuthorizationDeniedException {
        AdminGroupData result = null;
        if (roleAccessSession.findRole(newName) == null) {
            assertAuthorizedToEditRole(authenticationToken, role);
            final String oldName = role.getRoleName();
            
            // Create the role again with the new name to get the correct primary keys etc.
            Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
            for (AccessRuleData oldRule : role.getAccessRules().values()) {
                // Copy so we get a new id
                accessRules.add(new AccessRuleData(newName, oldRule.getAccessRuleName(), oldRule.getInternalState(), oldRule.getRecursive()));
            }
            
            Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            for (AccessUserAspectData user : role.getAccessUsers().values()) {
                user = new AccessUserAspectData(newName, user.getCaId(), user.getMatchWith(), user.getTokenType(), user.getMatchTypeAsType(), user.getMatchValue());
                subjects.add(user);
            }
            
            result = create(authenticationToken, newName);
            try {
                result = addAccessRulesToRole(authenticationToken, result, accessRules);
                result = addSubjectsToRole(authenticationToken, result, subjects);
                remove(authenticationToken, oldName);
            } catch (RoleNotFoundException e) {
                throw new RuntimeException(e); // Should never happen
            }

            accessTreeUpdateSession.signalForAccessTreeUpdate();
            accessControlSession.forceCacheExpire();

            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.rolerenamed", oldName, result.getRoleName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            securityEventsLogger.log(EventTypes.ROLE_RENAMING, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        } else {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorroleexists", newName);
            throw new RoleExistsException(msg);
        }

        return result;
    }

    @Override
    public AdminGroupData addAccessRulesToRole(AuthenticationToken authenticationToken, final AdminGroupData role, final Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException, AuthorizationDeniedException {
        assertAuthorizedToEditRole(authenticationToken, role);
        //Check that current aspect is authorized to all the rules she's planning on replacing
        if (!isAuthorizedToRules(authenticationToken, accessRules)) {
            throw new AuthorizationDeniedException(authenticationToken + " not authorized to all access rules.");
        }
        return addAccessRulesToRoleNoAuth(authenticationToken, role, accessRules);
    }

    private AdminGroupData addAccessRulesToRoleNoAuth(AuthenticationToken authenticationToken, final AdminGroupData role,
            final Collection<AccessRuleData> accessRules) throws RoleNotFoundException {
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
            if (accessRuleManagement.find(accessRule.getPrimaryKey()) == null) {
                accessRuleManagement.persistRule(accessRule);
                rulesAdded.add(accessRule);
            }
            // If the rule exists, then merely update its values.
            if (rules.containsKey(accessRule.getPrimaryKey())) {
                rules.remove(accessRule.getPrimaryKey());
                accessRule = accessRuleManagement.setState(accessRule, accessRule.getInternalState(), accessRule.getRecursive());
                rulesMerged.add(accessRule);
            }
            rules.put(accessRule.getPrimaryKey(), accessRule);
        }
        result.setAccessRules(rules);

        result = entityManager.merge(result);
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire();

        logAccessRulesAdded(authenticationToken, role.getRoleName(), rulesAdded);

        return result;
    }

    @Override
    public AdminGroupData removeAccessRulesFromRole(AuthenticationToken authenticationToken, AdminGroupData role, List<String> accessRuleNames)
            throws RoleNotFoundException, AuthorizationDeniedException {
        Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        for (String accessRuleName : accessRuleNames) {
            AccessRuleData rule = accessRuleManagement.find(AccessRuleData.generatePrimaryKey(role.getRoleName(), accessRuleName));
            if (rule != null) {
                accessRules.add(rule);
            }
        }
        return removeAccessRulesFromRole(authenticationToken, role, accessRules);
    }

    @Override
    public AdminGroupData removeAccessRulesFromRole(AuthenticationToken authenticationToken, final AdminGroupData role, Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException, AuthorizationDeniedException {
        AdminGroupData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }
        assertAuthorizedToEditRole(authenticationToken, role);
        // Check authorization for rule
        if(!isAuthorizedToRules(authenticationToken, accessRules)) {
            throw new AuthorizationDeniedException(authenticationToken + " not authorized to all access rules.");
        }     
        Map<Integer, AccessRuleData> resultAccessRules = result.getAccessRules();
        for (AccessRuleData accessRule : accessRules) {
            if (resultAccessRules.containsKey(accessRule.getPrimaryKey())) {
                // Due to optimistic locking, update accessRule
                accessRule = accessRuleManagement.find(accessRule.getPrimaryKey());
                resultAccessRules.remove(accessRule.getPrimaryKey());
                accessRuleManagement.remove(accessRule);
            } else {
                throw new AccessRuleNotFoundException("Access rule " + accessRule + " does not exist in role " + role + ", could not remove.");
            }
        }
        result.setAccessRules(resultAccessRules);
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire();

        logAccessRulesRemoved(authenticationToken, role.getRoleName(), accessRules);

        return result;
    }

    @Override
    public AdminGroupData addSubjectsToRole(AuthenticationToken authenticationToken, final AdminGroupData role, Collection<AccessUserAspectData> users)
            throws RoleNotFoundException, AuthorizationDeniedException {  
        assertAuthorizedToEditRole(authenticationToken, role);
        //Verify that authenticating user is authorized to all users
        StringBuilder sb = new StringBuilder();
        for(AccessUserAspectData accessUserAspectData : users) {
            int caId = accessUserAspectData.getCaId();
            if(!caSession.authorizedToCANoLogging(authenticationToken, caId)) {
                if(sb.length() > 0 ) {
                    sb.append("; ");
                }
                String msg = INTERNAL_RESOURCES.getLocalizedMessage("caadmin.notauthorizedtoca", authenticationToken.toString(), caId);
                sb.append(msg);
            }
        }
        if(sb.length() > 0) {
            throw new AuthorizationDeniedException(sb.toString());
        }
        
        return addSubjectsToRoleNoAuth(authenticationToken, role, users);
    }

    private AdminGroupData addSubjectsToRoleNoAuth(AuthenticationToken authenticationToken, final AdminGroupData role, Collection<AccessUserAspectData> users)
            throws RoleNotFoundException {
        if (roleAccessSession.findRole(role.getPrimaryKey()) == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }

        Map<Integer, AccessUserAspectData> existingUsers = role.getAccessUsers();
        final StringBuilder subjectsAdded = new StringBuilder();
        final StringBuilder subjectsChanged = new StringBuilder();
        for (AccessUserAspectData userAspect : users) {
            if(accessUserAspectSession.find(userAspect.getLegacyPrimaryKey()) != null) {
                //If an aspect exists using the old primary key, remove it so that we can replace it with the new one.
                accessUserAspectSession.remove(accessUserAspectSession.find(userAspect.getLegacyPrimaryKey()));
            }
            if (accessUserAspectSession.find(userAspect.getPrimaryKey()) == null) {
                // if userAspect hasn't been persisted, do so.
                try {
                    accessUserAspectSession.persistAccessUserAspect(userAspect);
                } catch (AccessUserAspectExistsException e) {
                    throw new IllegalStateException("Tried to persist user aspect with primary key " + userAspect.getPrimaryKey()
                            + " which was apparently found in the database in spite of a previous check.");
                }
            }

            if (existingUsers.containsKey(userAspect.getPrimaryKey())) {
                existingUsers.remove(userAspect.getPrimaryKey());
                subjectsChanged.append("[" + userAspect.toString() + "]");
            } else {
                subjectsAdded.append("[" + userAspect.toString() + "]");
            }
            existingUsers.put(userAspect.getPrimaryKey(), userAspect);
            
            
        }
        role.setAccessUsers(existingUsers);
        AdminGroupData result = entityManager.merge(role);
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire(); 
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

    @Override
    public AdminGroupData removeSubjectsFromRole(AuthenticationToken authenticationToken, final AdminGroupData role, Collection<AccessUserAspectData> subjects)
            throws RoleNotFoundException, AuthorizationDeniedException {
        AdminGroupData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }

        assertAuthorizedToEditRole(authenticationToken, role);
        StringBuilder subjectStrings = new StringBuilder();
        Map<Integer, AccessUserAspectData> accessUsersFromResult = result.getAccessUsers();
        for (AccessUserAspectData subject : subjects) {
            if (accessUsersFromResult.containsKey(subject.getPrimaryKey())) {
                subject = accessUserAspectSession.find(subject.getPrimaryKey());
                accessUsersFromResult.remove(subject.getPrimaryKey());
                accessUserAspectSession.remove(subject);
                subjectStrings.append("[" + subject.toString() + "]");
            } else {
                throw new AccessUserAspectNotFoundException("Access user aspect " + subject + " not found in role " + role);
            }
        }
        result.setAccessUsers(accessUsersFromResult);
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire();

        final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.adminremoved", subjectStrings, role.getRoleName());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        securityEventsLogger.log(EventTypes.ROLE_ACCESS_USER_DELETION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                authenticationToken.toString(), null, null, null, details);

        return result;

    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    /*
     */
    public Collection<AdminGroupData> getAllRolesAuthorizedToEdit(AuthenticationToken authenticationToken) {
        List<AdminGroupData> result = new ArrayList<AdminGroupData>();
        for (AdminGroupData role : roleAccessSession.getAllRoles()) {
            if (isAuthorizedToRole(authenticationToken, role)) {
                result.add(role);
            }
        }
        return result;
    }
        
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isAuthorizedToRole(AuthenticationToken authenticationToken, AdminGroupData role) {
        if (role == null) {
            return false;
        }
        // Firstly, make sure that authentication token authorized for all access user aspects in role, by checking against the CA that produced them.
        for (AccessUserAspectData accessUserAspect : role.getAccessUsers().values()) {
            if (!caSession.authorizedToCA(authenticationToken, accessUserAspect.getCaId())) {
                return false;
            }
        }
        Map<Integer, AccessRuleData> accessRules = role.getAccessRules();
        if (!isAuthorizedToRules(authenticationToken, accessRules.values())) {
            return false;
        }
        // The admin may have resources denied to itself, and if role has access to any of these, the admin should not have access
        // to that role. 
        Set<String> ruleCache = new HashSet<String>();
        List<String> deniedRules = new LinkedList<String>();
        try {
            // AuthenticationToken may match several roles. Go through each of them and if any denied rules are found, add them if they belong to the 
            // preferred role. 
            for(String roleName : roleAccessSession.getRolesMatchingAuthenticationToken(authenticationToken)) {
               for(AccessRuleData accessRule : roleAccessSession.findRole(roleName).getAccessRules().values()) {
                   String rule = accessRule.getAccessRuleName();
                   //Ignore if this rule has already been checked 
                   if(!ruleCache.contains(rule)) {  
                       ruleCache.add(rule);    
                       // If this rule is deny and dominant (due to the Role it belongs to being dominant over another Role that may contain the same rule
                       // with a different setting), cache it away
                       if(!accessControlSession.isAuthorizedNoLogging(authenticationToken, rule)) {
                           deniedRules.add(rule);                                           
                       }
                   }
               }
            }
        } catch (AuthenticationFailedException e) {
            throw new IllegalArgumentException("AuthenticationToken " + authenticationToken + " was not valid.", e);
        }
        //If our role has access to any of the rules that the admin was denied to, then we're a no go. 
        for(String deniedRule : deniedRules) {
            if(role.hasAccessToRule(deniedRule)) {
                return false;
            }
        }

        return true;
    }
  
    /**
     * Asserts that authentication token is authorized to edit roles in general. 
     * 
     * @param authenticationToken a token for the authenticating entity
     * @throws AuthorizationDeniedException if not authorized
     */
    private void assertAuthorizedToEditRoles(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
        if (!accessControlSession.isAuthorized(authenticationToken, StandardRules.EDITROLES.resource())) {
            String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.notauthorizedtoeditroles", authenticationToken.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }
    
    /**
     * Asserts that authentication token is authorized to edit roles in general, and to modify a role in particular.
     * 
     * @param authenticationToken a token for the authenticating entity
     * @param role the role to check.
     * @throws AuthorizationDeniedException if not authorized
     */
    private void assertAuthorizedToEditRole(final AuthenticationToken authenticationToken, final AdminGroupData role) throws AuthorizationDeniedException {
        assertAuthorizedToEditRoles(authenticationToken);
        if(!isAuthorizedToRole(authenticationToken, role)) {
            String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.notauthorizedtoeditrole", authenticationToken.toString(), role.getRoleName());
            throw new AuthorizationDeniedException(msg);
        }
    }
    
    @Override
    public boolean isAuthorizedToRules(AuthenticationToken authenticationToken, Collection<AccessRuleData> rules) {
        for (AccessRuleData accessRule : rules) {
            String rule = accessRule.getAccessRuleName();
            /*
             * Recursive rules and nonrecursive rules need to be checked differently. If the current rule being checked
             * is recursive, then recursivity has to be matched as well.
             */
            if(accessRule.getTreeState() == AccessTreeState.STATE_ACCEPT) {
                if (!accessControlSession.isAuthorizedNoLogging(authenticationToken, false, rule)) {
                    log.debug(authenticationToken + " not authorized to " + rule); 
                    return false;
                }
            } else if(accessRule.getTreeState() == AccessTreeState.STATE_ACCEPT_RECURSIVE) {
                if (!accessControlSession.isAuthorizedNoLogging(authenticationToken, true, rule)) {
                    log.debug(authenticationToken + " not authorized to " + rule + " (recursive)");
                    return false;
                }
            }
        }
        return true;
    }
    
    @Override
    public List<AdminGroupData> getAuthorizedRoles(AuthenticationToken admin, String resource) {
        return getAuthorizedRoles(admin, resource, false);
    }
    
    @Override
    public List<AdminGroupData> getAuthorizedRoles(String resource, boolean requireRecursive) {
        return getAuthorizedRoles(roleAccessSession.getAllRoles(), resource, requireRecursive);
    }
    
    private  List<AdminGroupData> getAuthorizedRoles(Collection<AdminGroupData> roles, String resource, boolean requireRecursive) {
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
            AlwaysAllowLocalAuthenticationToken token = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RoleManagementSessionBean.getAuthorizedRoles"));
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
    
    @Override
    public List<AdminGroupData> getAuthorizedRoles(AuthenticationToken admin, String resource, boolean requireRecursive) {
        // Look for Roles that have access rules that allows the group access to the rule below.
        Collection<AdminGroupData> roles = getAllRolesAuthorizedToEdit(admin);       
        return getAuthorizedRoles(roles, resource, requireRecursive);
    }

    @Override
    public AdminGroupData replaceAccessRulesInRole(final AuthenticationToken authenticationToken, final AdminGroupData role,
            final Collection<AccessRuleData> accessRules) throws AuthorizationDeniedException, RoleNotFoundException {
        assertAuthorizedToEditRole(authenticationToken, role);
        //Check that current aspect is authorized to all the rules she's planning on replacing
        if(!isAuthorizedToRules(authenticationToken, accessRules)) {
            throw new AuthorizationDeniedException(authenticationToken + " not authorized to all access rules.");
        }

        AdminGroupData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }

        Map<Integer, AccessRuleData> rulesFromResult = result.getAccessRules();
        Map<Integer, AccessRuleData> rulesToResult = new HashMap<Integer, AccessRuleData>();
        //Lists for logging purposes.
        Collection<AccessRuleData> newRules = new ArrayList<AccessRuleData>();
        Collection<AccessRuleData> changedRules = new ArrayList<AccessRuleData>();
        for (AccessRuleData rule : accessRules) {
            if (AccessRuleData.generatePrimaryKey(role.getRoleName(), rule.getAccessRuleName()) != rule.getPrimaryKey()) {
                throw new IllegalStateException("Role " + role.getRoleName() + " did not match up with the role that created this rule.");
            }
            Integer ruleKey = rule.getPrimaryKey();
            if (rulesFromResult.containsKey(ruleKey)) {
                AccessRuleData oldRule = rulesFromResult.get(ruleKey);
                if(!oldRule.equals(rule)) {
                    changedRules.add(oldRule);
                }
                AccessRuleData newRule = accessRuleManagement.setState(rule, rule.getInternalState(), rule.getRecursive());
                rulesFromResult.remove(ruleKey);
                rulesToResult.put(newRule.getPrimaryKey(), newRule);         
            } else {
                try {
                    newRules.add(accessRuleManagement.createRule(rule.getAccessRuleName(), result.getRoleName(), rule.getInternalState(),
                            rule.getRecursive()));
                } catch (AccessRuleExistsException e) {
                    throw new Error("Access rule exists, but wasn't found in persistence in previous call.", e);
                }
                rulesToResult.put(rule.getPrimaryKey(), rule);
            }

        }
        logAccessRulesAdded(authenticationToken, role.getRoleName(), newRules);
        logAccessRulesChanged(authenticationToken, role.getRoleName(), changedRules);

        //And for whatever remains:
        accessRuleManagement.remove(rulesFromResult.values());
        result.setAccessRules(rulesToResult);
        result = entityManager.merge(result);
        logAccessRulesRemoved(authenticationToken, role.getRoleName(), rulesFromResult.values());
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire();

        return result;
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

    private Integer findFreeRoleId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return roleAccessSession.findRole(Integer.valueOf(i)) == null;
            }
        };
        return Integer.valueOf(ProfileID.getNotUsedID(db));
    }



}
