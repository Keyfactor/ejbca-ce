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
package org.ejbca.core.model.authorization;

import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;

/**
 * Class to act as a placeholder for rule templates. It doesn't convey a primary key, since such a key depends on the role in question.
 * 
 * @version $Id$
 *
 */
public class AccessRuleTemplate {

    private String accessRuleName;
    private AccessRuleState state;
    private Boolean recursive;

    public AccessRuleTemplate(String accessRuleName, AccessRuleState state, Boolean recursive) {
        super();
        this.accessRuleName = accessRuleName;
        this.state = state;
        this.recursive = recursive;
    }

    /**
     * @return the accessRuleName
     */
    public String getAccessRuleName() {
        return accessRuleName;
    }

    /**
     * @return the internalState
     */
    public AccessRuleState getState() {
        return state;
    }

    /**
     * @return the recursive
     */
    public Boolean isRecursive() {
        return recursive;
    }

    /**
     * Creates a new AccessRuleData object using the given rolename
     * 
     * @param roleName the name of the role that this AccessRuleData belongs to. Required to generate primary key
     * @return a new AccessRuleData object
     */
    public AccessRuleData createAccessRuleData(String roleName) {
        return new AccessRuleData(roleName, accessRuleName, state, recursive);
    }

    /**
     * This method compares to a AccessRuleData object, and returns true if rule, state and recursive value are the same.
     * 
     * @param rule the rule to check against
     * @return true if rule, state and recursive value are the same.
     */
    public boolean compareToAccessRuleData(AccessRuleData rule) {
        return accessRuleName.equals(rule.getAccessRuleName()) && state == rule.getInternalState() && recursive == rule.getRecursive();
    }

}
