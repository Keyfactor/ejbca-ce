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

import java.security.cert.Certificate;
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
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleExistsException;
import org.cesecore.authorization.rules.AccessRuleManagementSessionLocal;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.AccessUserAspectManagerSessionLocal;
import org.cesecore.authorization.user.AccessUserAspectNotFoundException;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.ProfileID;

/**
 * Implementation of the RoleManagementSession interface.
 * 
 * Based on cesecore version: RoleManagementSessionBean.java 925 2011-07-04 11:41:17Z mikek
 * 
 * @version $Id$
 * 
 */
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
    private RoleAccessSessionLocal roleAccessSession;

    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public void initializeAccessWithCert(AuthenticationToken authenticationToken, String roleName, Certificate certificate)
            throws RoleExistsException, RoleNotFoundException {
        if (log.isTraceEnabled()) {
            log.trace(">initializeAccessWithCert: " + authenticationToken.toString() + ", " + roleName);
        }
        // Create a role
        RoleData role = createNoAuth(authenticationToken, roleName);

        // Create a user aspect that matches the authentication token, and add that to the role.
        List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
        accessUsers.add(new AccessUserAspectData(role.getRoleName(), CertTools.getIssuerDN(certificate).hashCode(),
                X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, CertTools.getPartFromDN(
                        CertTools.getSubjectDN(certificate), "CN")));
        addSubjectsToRoleNoAuth(authenticationToken, role, accessUsers);

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.EDITROLES.resource(), AccessRuleState.RULE_ACCEPT, true));
        addAccessRulesToRoleNoAuth(authenticationToken, role, accessRules);
        if (log.isTraceEnabled()) {
            log.trace("<initializeAccessWithCert: " + authenticationToken.toString() + ", " + roleName);
        }
    }

    @Override
    public RoleData create(AuthenticationToken authenticationToken, String roleName) throws RoleExistsException, AuthorizationDeniedException {
        // Authorized to edit roles?
        authorizedToEditRole(authenticationToken, roleName);

        return createNoAuth(authenticationToken, roleName);
    }

    private RoleData createNoAuth(AuthenticationToken authenticationToken, String roleName) throws RoleExistsException {
        if (roleAccessSession.findRole(roleName) == null) {
            RoleData role = new RoleData(findFreeRoleId(), roleName);
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
        final RoleData role = roleAccessSession.findRole(roleName);
        if (role == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", roleName);
            throw new RoleNotFoundException(msg);
        } else {
            // this remove check authorization
            remove(authenticationToken, role);
        }
    }

    @Override
    public void remove(AuthenticationToken authenticationToken, RoleData role) throws RoleNotFoundException, AuthorizationDeniedException {
        // Authorized to edit roles?
        authorizedToEditRole(authenticationToken, role.getRoleName());
        removeNoAuth(authenticationToken, role);
    }

    private void removeNoAuth(AuthenticationToken authenticationToken, RoleData role) throws RoleNotFoundException {
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
    public RoleData renameRole(AuthenticationToken authenticationToken, String role, String newName) throws RoleExistsException,
            AuthorizationDeniedException {
        return renameRole(authenticationToken, roleAccessSession.findRole(role), newName);
    }

    @Override
    public RoleData renameRole(AuthenticationToken authenticationToken, RoleData role, String newName) throws RoleExistsException,
            AuthorizationDeniedException {
        RoleData result = null;
        if (roleAccessSession.findRole(newName) == null) {
            // Authorized to edit roles?
            authorizedToEditRole(authenticationToken, role.getRoleName());
            final String oldName = role.getRoleName();
            role.setRoleName(newName);

            result = entityManager.merge(role);

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
    public RoleData addAccessRulesToRole(AuthenticationToken authenticationToken, final RoleData role, final Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException, AccessRuleNotFoundException, AuthorizationDeniedException {
        // Authorized to edit roles?
        authorizedToEditRole(authenticationToken, role.getRoleName());

        return addAccessRulesToRoleNoAuth(authenticationToken, role, accessRules);
    }

    private RoleData addAccessRulesToRoleNoAuth(AuthenticationToken authenticationToken, final RoleData role,
            final Collection<AccessRuleData> accessRules) throws RoleNotFoundException, AccessRuleNotFoundException {
        RoleData result = roleAccessSession.findRole(role.getPrimaryKey());
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
    public RoleData removeAccessRulesFromRole(AuthenticationToken authenticationToken, RoleData role, List<String> accessRuleNames)
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
    public RoleData removeAccessRulesFromRole(AuthenticationToken authenticationToken, final RoleData role, Collection<AccessRuleData> accessRules)
            throws RoleNotFoundException, AuthorizationDeniedException {
        RoleData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }
        // Authorized to edit roles?
        authorizedToEditRole(authenticationToken, result.getRoleName());
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
    public RoleData addSubjectsToRole(AuthenticationToken authenticationToken, final RoleData role, Collection<AccessUserAspectData> users)
            throws RoleNotFoundException, AuthorizationDeniedException {
        // Authorized to edit roles?
        authorizedToEditRole(authenticationToken, role.getRoleName());

        return addSubjectsToRoleNoAuth(authenticationToken, role, users);
    }

    private RoleData addSubjectsToRoleNoAuth(AuthenticationToken authenticationToken, final RoleData role, Collection<AccessUserAspectData> users)
            throws RoleNotFoundException {
        if (roleAccessSession.findRole(role.getPrimaryKey()) == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }

        Map<Integer, AccessUserAspectData> existingUsers = role.getAccessUsers();
        final StringBuilder subjectsAdded = new StringBuilder();
        final StringBuilder subjectsChanged = new StringBuilder();
        for (AccessUserAspectData userAspect : users) {
            // if userAspect hasn't been persisted, do so.
            if (accessUserAspectSession.find(userAspect.getPrimaryKey()) == null) {
                accessUserAspectSession.persistAccessUserAspect(userAspect);
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
        RoleData result = entityManager.merge(role);
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
            securityEventsLogger.log(EventTypes.ROLE_ACCESS_USER_ADDITION, EventStatus.SUCCESS, ModuleTypes.ROLES, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
        }
        return result;
    }

    @Override
    public RoleData removeSubjectsFromRole(AuthenticationToken authenticationToken, final RoleData role, Collection<AccessUserAspectData> subjects)
            throws RoleNotFoundException, AuthorizationDeniedException {
        RoleData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }

        // Authorized to edit roles?
        authorizedToEditRole(authenticationToken, result.getRoleName());
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
     * FIXME: Test this method! 
     */
    public Collection<RoleData> getAllRolesAuthorizedToEdit(AuthenticationToken authenticationToken) {
        List<RoleData> result = new ArrayList<RoleData>();
        for (RoleData role : roleAccessSession.getAllRoles()) {
            if (isAuthorizedToEditRole(authenticationToken, role)) {
                result.add(role);
            }
        }
        return result;
    }
    
    @Override
    public boolean isAuthorizedToEditRole(AuthenticationToken authenticationToken, RoleData role) {
        if (role == null) {
            return false;
        }
        // Firstly, make sure that authentication token authorized for all access user aspects in role, by checking against the CA that produced them.
        for (AccessUserAspectData accessUserAspect : role.getAccessUsers().values()) {
            if (!accessControlSession.isAuthorizedNoLogging(authenticationToken, false, StandardRules.CAACCESS.resource() + accessUserAspect.getCaId())) {
                return false;
            }
        }
        for (AccessRuleData accessRule : role.getAccessRules().values()) {
            String rule = accessRule.getAccessRuleName();
            if (!accessControlSession.isAuthorizedNoLogging(authenticationToken, false, rule)) {
                return false;
            }
        }
        // Everything's A-OK, role is good.
        return true;
    }
    
    @Override
    public Collection<RoleData> getAuthorizedRoles(AuthenticationToken admin, String resource) {
        ArrayList<RoleData> authissueingadmgrps = new ArrayList<RoleData>();
        // Look for Roles that have access rules that allows the group access to the rule below.
        Collection<RoleData> roles = getAllRolesAuthorizedToEdit(admin);
        Collection<RoleData> onerole = new ArrayList<RoleData>();
        for (RoleData role : roles) {
            // We want to check all roles if they are authorized, we can do that with a "private" AccessTree.
            // Probably quite inefficient but...
            AccessTree tree = new AccessTree();
            onerole.clear();
            onerole.add(role);
            tree.buildTree(onerole);
            // Create an AlwaysAllowAuthenticationToken just to find out if there is
            // an access rule for the requested resource
            AlwaysAllowLocalAuthenticationToken token = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("isGroupAuthorized"));
            try {
                if (tree.isAuthorized(token, resource)) {
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
    public RoleData replaceAccessRulesInRole(final AuthenticationToken authenticationToken, final RoleData role,
            final Collection<AccessRuleData> accessRules) throws AuthorizationDeniedException, RoleNotFoundException {
        authorizedToEditRole(authenticationToken, role.getRoleName());

        RoleData result = roleAccessSession.findRole(role.getPrimaryKey());
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
                throw new Error("Role " + role.getRoleName() + " did not match up with the role that created this rule.");
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

    private void authorizedToEditRole(AuthenticationToken authenticationToken, String roleName) throws AuthorizationDeniedException {
        if (!accessControlSession.isAuthorized(authenticationToken, StandardRules.EDITROLES.resource())) {
            String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.notauthorizedtoeditroles", authenticationToken.toString(), roleName);
            throw new AuthorizationDeniedException(msg);
        }
    }

}
