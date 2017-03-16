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

import javax.ejb.Local;

/**
 * Local interface for AccessRuleManagement
 * 
 * @version $Id$
 * 
 */
@Local
@Deprecated
public interface AccessRuleManagementSessionLocal {

    void persistRule(AccessRuleData rule);

    AccessRuleData createRule(String accessruleName, String roleName, AccessRuleState state, boolean isRecursive) throws AccessRuleExistsException;

    AccessRuleData find(int primaryKey);

    void remove(AccessRuleData accessRule);

    void remove(Collection<AccessRuleData> accessRules);

    AccessRuleData setState(AccessRuleData rule, AccessRuleState state, boolean isRecursive);
    
    /**
     * Check if any CA exists among the existing rules.
     * 
     * @param caid the ID of the CA to search for
     * @return true if the CA exists among the existing rules.
     */
    boolean existsCaInAccessRules(int caid);

}
