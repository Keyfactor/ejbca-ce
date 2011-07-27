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

import javax.ejb.Remote;

/**
 * Local interface for AccessRuleManagement
 * 
 * @version $Id: AccessRuleManagementTestSessionRemote.java 475 2011-03-09 09:54:43Z tomas $
 *
 */
@Remote
public interface AccessRuleManagementTestSessionRemote {

    /**
     * Persists a rule. 
     * @param rule
     */
    void persistRule(AccessRuleData rule);
    
    /**
     * Creates an access rule.
     * 
     * @param accessruleName Name of the created access rule. Is analog to a resource. 
     * @param roleName Name of the role that this rule belongs to. This value is used in generating the primary key.
     * @param state The state of this rule. 
     * @param isRecursive Whether or not this rule is recursive.
     * @return The created rule.
     * 
     * @throws AccessRuleExistsException if a rule by the name already exists.
     */
    AccessRuleData createRule(String accessruleName, String roleName, AccessRuleState state, boolean isRecursive) throws AccessRuleExistsException;
    
    /**
     * Finds and returns a rule by its primary key.
     * 
     * @param primaryKey 
     * @return The sought rule, or <code>null</code> if not found.
     */
    AccessRuleData find(int primaryKey);
    
    /**
     * Removes an access rule.
     * 
     * @param accessRule Access rule to remove.
     */
    void remove(AccessRuleData accessRule);
    
    /**
     * Removes a <code>Collection</code> of access rules.
     * 
     * @param accessRules A <code>Collection</code> of access rules.
     */
    void remove(Collection<AccessRuleData> accessRules);
    
    /**
     * Sets the state of a rule. Must be called from a transaction.
     * 
     * @param rule The rule to modify.
     * @param state The AccessRuleState to set.
     * @param isRecursive To set if recursive
     * @return the modified rule.
     */
    AccessRuleData setState(AccessRuleData rule, AccessRuleState state, boolean isRecursive);

}
