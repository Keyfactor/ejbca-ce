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
 
package org.ejbca.core.model.authorization;

import java.io.Serializable;
import java.util.Collection;
import java.util.Iterator;

/**
 * A class that builds and maintains an accesstree. It should be used to check if a
 * client certificate has access rights to a resource or not. isAuthorized method is the one to use.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class AccessTree implements Serializable {

    private AccessTreeNode rootnode = null;
	
    /** Builds an accesstree out of the given admingroup data. */
    public void buildTree(Collection<AdminGroup> admingroups) {
    	AccessTreeNode newRootnode = new AccessTreeNode("/");
                  
        Iterator<AdminGroup> iter = admingroups.iterator();
        // Add all admingroups accessrules.
        while(iter.hasNext()){
          AdminGroup admingroup = iter.next(); 
          Iterator<AccessRule> iter2 = admingroup.getAccessRules().iterator();
          while(iter2.hasNext()){
            AccessRule accessrule = iter2.next();  
            newRootnode.addAccessRule(accessrule.getAccessRule(),accessrule,admingroup); // Without heading '/' 
          }
        }
        rootnode = newRootnode;	// Replace the old access rules with the new ones
    }

    /** A method to check if someone is authorized to view the given resource */
    public boolean isAuthorized(AdminInformation admininformation, String resource){
    	String checkresource = resource;
        // Must begin with '/'.
        if((checkresource.toCharArray())[0] != '/') {
          checkresource = "/" + checkresource;
        }
        // Check if user is authorized in the tree.
        return rootnode.isAuthorized(admininformation, checkresource);
    }

}
