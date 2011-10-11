/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.roles;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleExistsException;
import org.cesecore.authorization.rules.AccessRuleManagementSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ComplexRoleManagementSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ComplexRoleManagementSessionBean implements ComplexRoleManagementSessionLocal, ComplexRoleManagementSessionRemote {

    /** Internal localization of logs and errors */
    private static final InternalResources INTERNAL_RESOURCES = InternalResources.getInstance();
    
    @EJB 
    private AccessRuleManagementSessionLocal accessRuleManagementSession;
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private AccessControlSessionLocal accessControlSession;
    @EJB
    private RoleAccessSessionRemote roleAccessSession;
  
      
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @Override
    public RoleData replaceAccessRulesInRole(AuthenticationToken authenticationToken, final RoleData role,
            final Collection<AccessRuleData> accessRules) throws AuthorizationDeniedException, RoleNotFoundException {
        authorizedToEditRole(authenticationToken, role.getRoleName());
        
        RoleData result = roleAccessSession.findRole(role.getPrimaryKey());
        if (result == null) {
            final String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.errorrolenotexists", role.getRoleName());
            throw new RoleNotFoundException(msg);
        }
       
        Map<Integer, AccessRuleData> rulesFromResult = result.getAccessRules();
        Map<Integer, AccessRuleData> rulesToResult = new HashMap<Integer, AccessRuleData>();
        for(AccessRuleData rule : accessRules) {
            if(AccessRuleData.generatePrimaryKey(role.getRoleName(), rule.getAccessRuleName()) != rule.getPrimaryKey()) {
                throw new Error("Role " + role.getRoleName() + " did not match up with the role that created this rule.");
            }
           Integer ruleKey = rule.getPrimaryKey();
            if(rulesFromResult.containsKey(ruleKey)) {
                AccessRuleData newRule = accessRuleManagementSession.setState(rule, rule.getInternalState(), rule.getRecursive());
                rulesFromResult.remove(ruleKey);
                rulesToResult.put(newRule.getPrimaryKey(), newRule);
            } else {
                try {
                    accessRuleManagementSession.createRule(rule.getAccessRuleName(), result.getRoleName(), rule.getInternalState(), rule.getRecursive());                   
                } catch (AccessRuleExistsException e) {
                    throw new Error("Access rule exists, but wasn't found in persistence in previous call.", e);
                }
                rulesToResult.put(rule.getPrimaryKey(), rule);
            } 
          
        }
        //And for whatever remains:
        accessRuleManagementSession.remove(rulesFromResult.values());

        result.setAccessRules(rulesToResult);
        result = entityManager.merge(result);
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire();
        
        return result;
    }
    
    private void authorizedToEditRole(AuthenticationToken authenticationToken, String roleName) throws AuthorizationDeniedException {
        if (!accessControlSession.isAuthorized(authenticationToken, StandardRules.EDITROLES.resource())) {
            String msg = INTERNAL_RESOURCES.getLocalizedMessage("authorization.notauthorizedtoeditroles", authenticationToken.toString(), roleName);
            throw new AuthorizationDeniedException(msg);
        }
    }
}
