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
 
package org.ejbca.core.model.hardtoken.profiles;

import java.rmi.RemoteException;
import java.util.HashMap;

import org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote;
import org.ejbca.core.model.log.Admin;

/**
 * A class used by PrimeCard clients to improve performance by caching hard token 
 * profiles locally, and only updating from database when the hard token profiles
 * have been edited.
 * 
 * This is needed since hard token profiles contains print image template data
 * and by removing the need to retrieving the profile for each card processed 
 * the network load will decrease dramatically.
 *
 * @version $Id: HardTokenProfileProxy.java,v 1.1 2006-01-17 20:31:52 anatom Exp $
 */
public class HardTokenProfileProxy {

    /** Creates a new instance of HardTokenProfileProxy */
    public HardTokenProfileProxy(Admin admin, IHardTokenSessionRemote hardtokensession){
                    
      this.hardtokensession = hardtokensession;
      this.profilestore = new HashMap();
	  this.updatecount = new HashMap();
      this.admin = admin;

    }

 
    /**
     * Method that first check the local store if the profile is upto date.
     *
     * @param profileid the id of the hard token profile. 
     * @return the hardtokenprofile or null if no profile exists with give id.
     */
    public HardTokenProfile getHardTokenProfile(int profileid) throws RemoteException {
      HardTokenProfile returnval = null;
      Integer id = new Integer(profileid);
      int count = 0;

      if(updatecount.get(id) == null ||
	    (count = hardtokensession.getHardTokenProfileUpdateCount(admin, profileid)) > ((Integer)  updatecount.get(id)).intValue()){         
        returnval = hardtokensession.getHardTokenProfile(admin, profileid);
        profilestore.put(id, returnval);
		updatecount.put(id, new Integer(count));
	  }
      return returnval;
    }

    // Private fields    
    private HashMap profilestore;
	private HashMap updatecount;
    private IHardTokenSessionRemote hardtokensession;    
    private Admin admin;

}
