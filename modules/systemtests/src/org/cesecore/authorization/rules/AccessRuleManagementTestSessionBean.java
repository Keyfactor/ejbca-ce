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
package org.cesecore.authorization.rules;

import java.util.Collection;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;

/**
 * Test session bean giving access to the local-only interface of AccessRuleManagementSessionBean, from remote EJB.
 * 
 * Based on cesecore version:
 *      AccessRuleManagementTestSessionBean.java 475 2011-03-09 09:54:43Z tomas
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessRuleManagementTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AccessRuleManagementTestSessionBean implements AccessRuleManagementTestSessionRemote {

    @EJB
    private AccessRuleManagementSessionLocal accessRuleManagement;
	
    @Override
    public AccessRuleData find(int primaryKey) {
    	return accessRuleManagement.find(primaryKey);
    }

    /*
     * @see org.cesecore.authorization.rules.AccessRuleManagementSession#remove(org.cesecore.authorization.rules.AccessRuleData)
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void remove(AccessRuleData accessRule) {
    	accessRuleManagement.remove(accessRule);
    }

    /*
     * @see org.cesecore.authorization.rules.AccessRuleManagementSession#remove(java.util.Collection)
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void remove(Collection<AccessRuleData> accessRules) {
    	accessRuleManagement.remove(accessRules);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.MANDATORY)
    public AccessRuleData setState(AccessRuleData rule, AccessRuleState state, boolean isRecursive) {
    	return accessRuleManagement.setState(rule, state, isRecursive);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public AccessRuleData createRule(String accessRuleName, String roleName, AccessRuleState state, boolean isRecursive) throws AccessRuleExistsException {
    	return accessRuleManagement.createRule(accessRuleName, roleName, state, isRecursive);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void persistRule(AccessRuleData rule) {
    	accessRuleManagement.persistRule(rule);
    }

}
