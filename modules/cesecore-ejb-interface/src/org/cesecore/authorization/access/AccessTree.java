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
package org.cesecore.authorization.access;

import java.util.Collection;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.roles.AdminGroupData;

/**
 * Maintains an access tree in memory
 * 
 * @version $Id$
 * 
 */
public class AccessTree {

    private AccessTreeNode rootNode = null;

    /**
     * Builds an access tree out of the given roles. In order to maintain consistency over several nodes connected to the same persistence layer, the
     * access tree needs to be refreshed at regular intervals with fresh data from the database.
     * 
     * This method is thread safe, and will protect the previous access tree while the new one is being built.
     * 
     * @param roles
     *            A collection of RoleData objects.
     */
    public synchronized void buildTree(Collection<AdminGroupData> roles) {
        AccessTreeNode newRootnode = new AccessTreeNode(StandardRules.ROLE_ROOT.resource());
        for (AdminGroupData role : roles) {
            for (AccessRuleData accessrule : role.getAccessRules().values()) {
                newRootnode.addAccessRule(accessrule.getAccessRuleName(), accessrule, role); // Without heading '/'
            }
        }
        rootNode = newRootnode; // Replace the old access rules with the new ones
    }
    
    /**
     * A method to check the authenticated user is authorized to view the given resource
     * 
     * @param authenticationToken
     *            A token from a successfully performed authentication.
     * @param resource
     *            The resource to check authorization for.
     * @param requireRecursive true if only accept recursive values should be accepted. 
     * @return true if authorization is granted.
     * @throws AuthenticationFailedException if any authentication errors were encountered during authorization process
     */
    public boolean isAuthorized(AuthenticationToken authenticationToken, String resource, final boolean requireRecursive) throws AuthenticationFailedException {
        String checkresource = resource;
        // Must begin with '/'.
        if ((checkresource.toCharArray())[0] != '/') {
            checkresource = "/" + checkresource;
        }
        // Check if user is authorized in the tree.
        return rootNode.isAuthorized(authenticationToken, checkresource, requireRecursive);
    }

}
