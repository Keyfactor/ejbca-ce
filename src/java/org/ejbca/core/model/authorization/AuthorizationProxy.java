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

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;


/**
 * A class used to improve performance by proxying administrator authorization request by minimizing the need of traversing
 * trough the authorization tree and rmi lookups. 
 *
 * @author  TomSelleck
 * @version $Id$
 */
public class AuthorizationProxy implements Serializable {
	private static final Logger log = Logger.getLogger(AuthorizationProxy.class);
	
	private static final long serialVersionUID = 1L;
	
    // Private fields.
    private HashMap<Integer, Boolean> authstore;
    private HashMap<Integer, Boolean> groupstore;
    private AccessTree accesstree;
    
    private boolean cliEnabled;

    
    /** Creates a new instance of AuthorizationProxy. */
    public AuthorizationProxy(final AccessTree accesstree, final boolean cliEnabled) {
       authstore = new HashMap();
       groupstore = new HashMap();
       this.accesstree = accesstree;
       this.cliEnabled = cliEnabled;
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
        if (log.isDebugEnabled()) {
        	log.debug("Is special user: "+adm);
    	}
        // If we are special admin, verify local auth token to make
        // sure that special admin can only be used inside this jvm
        if (!ArrayUtils.isEquals(admin.getLocalAuthToken(), AdminInformation.randomToken)) {
        	if ((adm == AdminEntity.SPECIALADMIN_BATCHCOMMANDLINEADMIN) ||
        			(adm == AdminEntity.SPECIALADMIN_CACOMMANDLINEADMIN) ||
        			(adm == AdminEntity.SPECIALADMIN_RAADMIN)) {
            	log.info("Failed internal admin check, but this is a command line client so allow it anyhow.");        
            	if (!cliEnabled) {
            		// CLI access disabled
            		log.info("Command line client access is disabled");
            		return false;
            	}
        	} else {
        		log.info("Failed internal admin check, and it's not a command line client");
        		return false;
        	}
        }
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
