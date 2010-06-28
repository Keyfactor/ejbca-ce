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
 
/*
 * cProfileNameProxy.java
 *
 * Created on den 23 juli 2002, 17:49
 */

package org.ejbca.ui.web.admin.rainterface;
import java.util.HashMap;

import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.model.log.Admin;

/**
 * A class used to improve performance by proxying end entity profileid to profilename mappings by minimizing the number of needed lockups over rmi.
 * 
 * @author  TomSelleck
 * @version $Id: EndEntityProfileNameProxy.java 7709 2009-06-11 12:09:36Z anatom $
 */
public class EndEntityProfileNameProxy implements java.io.Serializable {
    
    /** Creates a new instance of ProfileNameProxy */
    public EndEntityProfileNameProxy(Admin administrator, IRaAdminSessionLocal raadminsession){
              // Get the RaAdminSession instance.
      this.raadminsession = raadminsession;  
      
      profilenamestore = new HashMap(); 
      this.administrator = administrator;  
    }
    
    /**
     * Method that first tries to find profilename in local hashmap and if it doesn't exists looks it up over RMI.
     *
     * @param profileid the profile id number to look up.
     * @return the profilename or null if no profilename is relatied to the given id
     */
    public String getEndEntityProfileName(int profileid) {
      String returnval = null;  
      // Check if name is in hashmap
      returnval = (String) profilenamestore.get(new Integer(profileid));
      
      if(returnval==null){
        // Retreive profilename
        returnval = raadminsession.getEndEntityProfileName(administrator, profileid);
        if(returnval != null) {
          profilenamestore.put(new Integer(profileid),returnval);
        }
      }    
       
      return returnval;
    }
    
    // Private fields
    private HashMap profilenamestore;
    private IRaAdminSessionLocal raadminsession;
    private Admin   administrator;

}
