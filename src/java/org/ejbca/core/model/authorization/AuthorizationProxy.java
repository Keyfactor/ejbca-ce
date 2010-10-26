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
import java.util.HashMap;

import org.ejbca.util.CertTools;


/**
 * A class used to improve performance by proxying administrator authorization request by minimizing the need of traversing
 * trough the authorization tree and rmi lookups. 
 *
 * @author  TomSelleck
 * @version $Id$
 */
public class AuthorizationProxy implements Serializable {
    private static final long serialVersionUID = 1L;
    // Private fields.
    private HashMap<Integer, Boolean> authstore;
    private HashMap<Integer, Boolean> groupstore;
    private AccessTree accesstree;

    
    /** Creates a new instance of AuthorizationProxy. */
    public AuthorizationProxy(AccessTree accesstree) {
       authstore = new HashMap<Integer, Boolean>();
       groupstore = new HashMap<Integer, Boolean>();
       this.accesstree = accesstree;
    }


    /**
     * Method that first checks in hashmap if administrator already have been checked in accesstree.
     * If not it looks in the accesstree.
     * @return true if authorized, false if not
     */
    public boolean isAuthorized(AdminInformation admin, String resource){
      Boolean returnval = null;
      int adm = 0;
      
      if (admin.isSpecialUser()) {
        adm = admin.getSpecialUser();
      } else {
        adm = CertTools.getSerialNumber(admin.getX509Certificate()).hashCode();
      }
      int tmp = adm ^ resource.hashCode();
        // Check if name is in hashmap
      returnval = authstore.get(tmp);
      
      if(returnval==null){          
        // Get authorization from access tree
          returnval = accesstree.isAuthorized(admin, resource);
          authstore.put(tmp,returnval);      
        }

      return returnval;
    }

    /**
     * Lookup in the cache if the AdminGroup is authorized to the specified resource
     * @param adminGroupId The id of the AdminGroup
     * @param resource The resource that we want check authorization for
     * @return
     */
    public boolean isGroupAuthorized(int adminGroupId, String resource) {
    	Boolean returnval = null;
    	int hashMapKey = adminGroupId ^ resource.hashCode();
    	// Check if the AdminGroup is present in the HashMap
    	Boolean o = groupstore.get(hashMapKey);
    	if (returnval==null) {
    		// Get authorization from access tree
    		AdminInformation admgroup = AdminInformation.getAdminInformationByGroupId(adminGroupId);				
    		returnval = accesstree.isAuthorized(admgroup, resource) || accesstree.isAuthorized(admgroup, "/super_administrator");
    		groupstore.put(hashMapKey,returnval);
    	} else {
    		returnval = o;
    	}
    	return returnval;
    }

    /**
     * Method used to clear the proxy, should be called every time administrator privileges have been
     * changed. 
     */
    public void clear(){
      this.authstore.clear();
      this.groupstore.clear();   
    }

}
