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
 
package se.anatom.ejbca.webdist.hardtokeninterface;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.TreeMap;

import se.anatom.ejbca.authorization.AdminGroup;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.hardtoken.HardTokenIssuerData;
import se.anatom.ejbca.hardtoken.IHardTokenSessionLocal;
import se.anatom.ejbca.log.Admin;

/**
 * A class that looks up the which Hard Token Issuers the administrator is authorized to view and edit
 * 
 * @version $Id: HardTokenAuthorization.java,v 1.5 2004-05-10 16:11:49 herrvendil Exp $
 */
public class HardTokenAuthorization implements Serializable {
    
  
    
    /** Creates a new instance of CAAuthorization. */
    public HardTokenAuthorization(Admin admin,  
                           IHardTokenSessionLocal hardtokensession, 
                           IAuthorizationSessionLocal authorizationsession) {
      this.admin=admin;
      this.hardtokensession=hardtokensession;            
      this.authorizationsession=authorizationsession;
    }

    /**
     * Method returning a TreeMap containing Hard Token Alias -> Hard Token Issuer Data
     * the administrator is authorized to view and edit
     * @return A TreeMap Hard Token Alias (String) -> HardTokenIssuerData
     */    
    public TreeMap getHardTokenIssuers(){  
      if(hardtokenissuers==null){            
		hardtokenissuers = new TreeMap();            
		Iterator iter = authorizationsession.getAuthorizedAdminGroupNames(admin).iterator();
		HashSet authadmingroupids = new HashSet(); 
	    while(iter.hasNext()){
		  AdminGroup next = (AdminGroup) iter.next();
		  authadmingroupids.add(new Integer(next.getAdminGroupId()));
	    }
		TreeMap allhardtokenissuers = this.hardtokensession.getHardTokenIssuers(admin);
		iter = allhardtokenissuers.keySet().iterator();
		while(iter.hasNext()){          
	      String alias = (String) iter.next();
		  if(authadmingroupids.contains(new Integer(((HardTokenIssuerData) allhardtokenissuers.get(alias)).getAdminGroupId()))){                    
			hardtokenissuers.put(alias,allhardtokenissuers.get(alias));
		  }   
		}    				        
      }
      
      return hardtokenissuers;  
    }
    
	/**
	 * Method returning a TreeMap containing Hard Token Profile Name -> Hard Token Profile Id
	 * the administrator is authorized to view and edit
	 * @return A TreeMap Hard Token Profile Name (String) -> Hard Token Profile Id
	 */    
	public TreeMap getHardTokenProfiles(){  
	  if(hardtokenprofiles==null){            
		hardtokenprofiles = new TreeMap();                
		Collection authorizedhardtokenprofiles = hardtokensession.getAuthorizedHardTokenProfileIds(admin);
		
		Iterator iter = authorizedhardtokenprofiles.iterator();
		while(iter.hasNext()){
		  Integer id = ((Integer) iter.next());	          
		  String name = hardtokensession.getHardTokenProfileName(admin,id.intValue());
		  hardtokenprofiles.put(name, id);		    
		}        
	  }      
	  return hardtokenprofiles;  
	}
    
    
    /**
     * Checks if administrator is authorized to edit the specified hard token issuer.
     * 
     * @param alias of hard token issuer
     * @return true if administrator is authorized to edit ahrd token issuer.
     */
    
    public boolean authorizedToHardTokenIssuer(String alias){
    	boolean returnval = false;
    	try{
    	  returnval = this.authorizationsession.isAuthorizedNoLog(admin,"/hardtoken_functionality/edit_hardtoken_issuers");
    	}catch(AuthorizationDeniedException ade){}
    	
    	return returnval && this.getHardTokenIssuers().keySet().contains(alias);    	
    }

	/**
	 * Checks if administrator is authorized to edit the specified hard token profile.
	 * 
	 * @param alias of hard token profile
	 * @return true if administrator is authorized to edit hard token profile.
	 */
    
	public boolean authorizedToHardTokenProfile(String name){
		boolean returnval = false;
		try{
		  returnval = this.authorizationsession.isAuthorizedNoLog(admin,"/hardtoken_functionality/edit_hardtoken_profiles");
		}catch(AuthorizationDeniedException ade){}
    	
		return returnval && this.getHardTokenProfiles().keySet().contains(name);    	
	}

    
	/**
	 * Returns a Map of hard token profile id (Integer) -> hard token profile name (String).
	 */
	public HashMap getHardTokenProfileIdToNameMap(){
	  if(hardtokenprofilesnamemap == null){
		hardtokenprofilesnamemap = this.hardtokensession.getHardTokenProfileIdToNameMap(admin); 
	  }
      
	  return hardtokenprofilesnamemap;
	}        
    
    /**
     * Returns a Collection of AdminGroup names authorized to issue hard tokens,
     * it also only returns the admin groups the administrator is authorized to edit.
     */
    public Collection getHardTokenIssuingAdminGroups(){
      if(authissueingadmgrps == null){
      	authissueingadmgrps = new ArrayList();
        Iterator iter = authorizationsession.getAuthorizedAdminGroupNames(admin).iterator();
        while(iter.hasNext()){
          AdminGroup next = (AdminGroup) iter.next();	
          try {          	
			if(authorizationsession.isGroupAuthorizedNoLog(admin, next.getAdminGroupId() ,"/hardtoken_functionality/issue_hardtokens"))
			  authissueingadmgrps.add(next);
		  } catch (AuthorizationDeniedException e) {}	          
        }      		
      }
    	
      return authissueingadmgrps;	
    }
    
    public void clear(){      
	  hardtokenissuers=null;
	  hardtokenprofiles=null;
	  hardtokenprofilesnamemap=null;
	  authissueingadmgrps=null;
    }    
    
    // Private fields.    
    private TreeMap hardtokenissuers = null;
	private TreeMap hardtokenprofiles = null;
	private HashMap hardtokenprofilesnamemap=null;
	private ArrayList authissueingadmgrps = null;
	
    private Admin admin;
    private IHardTokenSessionLocal hardtokensession;
    private IAuthorizationSessionLocal authorizationsession;    

}


