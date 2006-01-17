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
 * client certificate has access rights to a resource or not. isAthorized metod is the one to use.
 *
 * @author  Philip Vendil
 * @version $Id: AccessTree.java,v 1.1 2006-01-17 20:30:56 anatom Exp $
 */
public class AccessTree implements Serializable {
    /** Creates a new instance of AccessTree */
    public AccessTree() {}

    // Public methods
    /** Builds an accesstree out of the given admingroup data. */
    public void buildTree(Collection admingroups) {
        rootnode = new AccessTreeNode("/");
                  
        Iterator iter = admingroups.iterator();
        // Add all admingroups accessrules.
        while(iter.hasNext()){
          AdminGroup admingroup = (AdminGroup) iter.next(); 
          Iterator iter2 = admingroup.getAccessRules().iterator();
          while(iter2.hasNext()){
            AccessRule accessrule = (AccessRule) iter2.next();  
            rootnode.addAccessRule(accessrule.getAccessRule(),accessrule,admingroup); // Without heading '/' 
          }
        }
    }

    /** A method to check if someone is athorized to view the given resource */
    public boolean isAuthorized(AdminInformation admininformation, String resource){
          String checkresource = resource;
        // Must begin with '/'.
        if((checkresource.toCharArray())[0] != '/')
          checkresource = "/" + checkresource;

        // Check if user is athorized in the tree.
        boolean retval = rootnode.isAuthorized(admininformation, checkresource);
        return retval;
    }



    // Private fields
    private AccessTreeNode rootnode = null;

}
