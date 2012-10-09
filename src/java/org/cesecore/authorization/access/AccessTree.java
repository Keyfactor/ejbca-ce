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
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.roles.RoleData;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * Maintains an access tree in memory
 * 
 * Based on EJBCA version:
 *      AccessTree.java 9993 2010-09-27 07:12:52Z anatom
 * Based on cesecore version:
 *      AccessTree.java 790 2011-05-16 14:45:05Z johane
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
    public synchronized void buildTree(Collection<RoleData> roles) {
        AccessTreeNode newRootnode = new AccessTreeNode(AccessRulesConstants.ROLE_ROOT);
        for (RoleData role : roles) {
            for (AccessRuleData accessrule : role.getAccessRules().values()) {
                newRootnode.addAccessRule(accessrule.getAccessRuleName(), accessrule, role); // Without heading '/'
            }
        }
        rootNode = newRootnode; // Replace the old access rules with the new ones
    }

    /**
     * A method to check the authenticated user is authorized to view the given resource
     * 
     * Will by default accept recursive accept values. 
     * 
     * @param authenticationToken
     *            A token from a successfully performed authentication.
     * @param resource
     *            The resource to check authorization for.
     * @return True if authorization is granted.
     * @throws AuthenticationFailedException if any authentication errors were encountered during authorization process
     */
    public boolean isAuthorized(AuthenticationToken authenticationToken, String resource) throws AuthenticationFailedException {
       return isAuthorized(authenticationToken, resource, true);
    }
    
    /**
     * A method to check the authenticated user is authorized to view the given resource
     * 
     * @param authenticationToken
     *            A token from a successfully performed authentication.
     * @param resource
     *            The resource to check authorization for.
     * @param acceptRecursive true of recursive values should be accepted. If false, only explicit accept rules will grant authorization. 
     * @return true if authorization is granted.
     * @throws AuthenticationFailedException if any authentication errors were encountered during authorization process
     */
    public boolean isAuthorized(AuthenticationToken authenticationToken, String resource, final boolean acceptRecursive) throws AuthenticationFailedException {
        String checkresource = resource;
        // Must begin with '/'.
        if ((checkresource.toCharArray())[0] != '/') {
            checkresource = "/" + checkresource;
        }
        // Check if user is authorized in the tree.
        return rootNode.isAuthorized(authenticationToken, checkresource, acceptRecursive);
    }

}
