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
 
package org.ejbca.ui.web.admin.hardtokeninterface;

import java.io.Serializable;
import java.util.HashMap;
import java.util.TreeMap;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * A class that looks up the which Hard Token Issuers the administrator is authorized to view and edit
 * 
 * @version $Id$
 */
public class HardTokenAuthorization implements Serializable {

    private static final long serialVersionUID = 164749645578145734L;
  
    private TreeMap<String, Integer> hardtokenprofiles = null;
    private HashMap<Integer, String>  hardtokenprofilesnamemap = null;

    private AuthenticationToken admin;
    private HardTokenSession hardtokensession;
    private AuthorizationSessionLocal authorizationSession;

    /** Creates a new instance of CAAuthorization. */
    public HardTokenAuthorization(AuthenticationToken authenticationToken, HardTokenSession hardtokensession, AuthorizationSessionLocal authorizationSession) {
      this.admin = authenticationToken;
      this.hardtokensession = hardtokensession;
      this.authorizationSession = authorizationSession;
    }
    
	/**
	 * Method returning a TreeMap containing Hard Token Profile Name -> Hard Token Profile Id
	 * the administrator is authorized to view and edit
	 * @return A TreeMap Hard Token Profile Name (String) -> Hard Token Profile Id
	 */    
	public TreeMap<String, Integer> getHardTokenProfiles(){  
	  if(hardtokenprofiles==null){            
		hardtokenprofiles = new TreeMap<String, Integer>();                	
		for(Integer id :  hardtokensession.getAuthorizedHardTokenProfileIds(admin)){		       
		  String name = hardtokensession.getHardTokenProfileName(id.intValue());
		  hardtokenprofiles.put(name, id);		    
		}        
	  }      
	  return hardtokenprofiles;  
	}
    
    /**
     * Checks if administrator is authorized to edit the specified hard token
     * profile.
     * 
     * @param alias
     *            of hard token profile
     * @return true if administrator is authorized to edit hard token profile.
     */

    public boolean authorizedToHardTokenProfile(String name) {
        return authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES)
                && this.getHardTokenProfiles().keySet().contains(name);
    }

    /**
     * Returns a Map of hard token profile id (Integer) -> hard token profile
     * name (String).
     */
    public HashMap<Integer, String>  getHardTokenProfileIdToNameMap() {
        if (hardtokenprofilesnamemap == null) {
            hardtokenprofilesnamemap = this.hardtokensession.getHardTokenProfileIdToNameMap();
        }

        return hardtokenprofilesnamemap;
    }

    public void clear(){      
	  hardtokenprofiles=null;
	  hardtokenprofilesnamemap=null;
    }
}
