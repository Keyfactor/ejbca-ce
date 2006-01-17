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
 
package org.ejbca.core.model.ra;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;

import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.log.Admin;

/**
 * A class that looks up the which CA:s or end entity profiles the administrator is authorized to view.
 * 
 * @version $Id: RAAuthorization.java,v 1.1 2006-01-17 20:28:07 anatom Exp $
 */
public class RAAuthorization implements Serializable {
    
  
    
    /** Creates a new instance of RAAuthorization. */
    public RAAuthorization(Admin admin, IRaAdminSessionLocal raadminsession, IAuthorizationSessionLocal authorizationsession) {
      this.admin=admin;
      this.raadminsession=raadminsession;
      this.authorizationsession=authorizationsession;
    }

    
    
    /**
     * Method that checks the administrators CA privileges and returns a string that should be used in where clause of userdata SQL queries.
     *
     * @return a string of administrators CA privileges that should be used in the where clause of SQL queries.
     */
    public String getCAAuthorizationString() {      
      if(authcastring==null){
        Iterator iter =  this.authorizationsession.getAuthorizedCAIds(admin).iterator();
         
        authcastring = "";
        
        while(iter.hasNext()){
          if(authcastring.equals(""))
            authcastring = " caid = " + ((Integer) iter.next()).toString();   
          else    
            authcastring = authcastring + " OR caid = " + ((Integer) iter.next()).toString(); 
        }
        
        if(!authcastring.equals(""))
          authcastring = "( " + authcastring + " )"; 
 
      }
      
      return authcastring;
    } 
    
    /**
     * Method that checks the administrators end entity profile privileges and returns a string that should be used in where clause of userdata SQL queries.
     *
     * @return a string of end entity profile privileges that should be used in the where clause of SQL queries.
     */
    public String getEndEntityProfileAuthorizationString(){
      if(authendentityprofilestring==null){
      	Collection result = this.authorizationsession.getAuthorizedEndEntityProfileIds(admin, AvailableAccessRules.VIEW_RIGHTS);     	
      	result.retainAll(this.raadminsession.getAuthorizedEndEntityProfileIds(admin));
      	Iterator iter = result.iterator();
      	                    
        while(iter.hasNext()){
          if(authendentityprofilestring == null)
            authendentityprofilestring = " endEntityprofileId = " + ((Integer) iter.next()).toString();   
          else    
            authendentityprofilestring = authendentityprofilestring + " OR endEntityprofileId = " + ((Integer) iter.next()).toString(); 
        }
        
        if(authendentityprofilestring != null)
          authendentityprofilestring = "( " + authendentityprofilestring + " )"; 
          
      }
        
      return authendentityprofilestring; 
    }
    
    
    public TreeMap getAuthorizedEndEntityProfileNames(){
      if(authprofilenames==null){
        authprofilenames = new TreeMap();  
        Iterator iter = raadminsession.getAuthorizedEndEntityProfileIds(admin).iterator();      
        HashMap idtonamemap = raadminsession.getEndEntityProfileIdToNameMap(admin);
        while(iter.hasNext()){
          Integer id = (Integer) iter.next();
          authprofilenames.put(idtonamemap.get(id),id);
        }
      }
      return authprofilenames;  
    }
    
	public TreeMap getCreateAuthorizedEndEntityProfileNames() {
		if(authcreateprofilenames == null){
			authcreateprofilenames = this.authEndEntityProfileNames(AvailableAccessRules.CREATE_RIGHTS);
		}
	       
		return authcreateprofilenames;  
	}
	      
	public TreeMap getViewAuthorizedEndEntityProfileNames(){
	  if(authviewprofilenames == null){
	  	  authviewprofilenames = this.authEndEntityProfileNames(AvailableAccessRules.VIEW_RIGHTS);
	  }
	  
      
	  return authviewprofilenames;
	}    
    
    public void clear(){
      authcastring=null;
      authendentityprofilestring=null;
      authprofilenames = null;
	  authcreateprofilenames = null;
	  authviewprofilenames = null;
    }
    
    
	public TreeMap authEndEntityProfileNames(String rights) {
	  TreeMap returnval = new TreeMap();	
	  HashMap profilemap = this.raadminsession.getEndEntityProfileIdToNameMap(admin);
	  Iterator iter = raadminsession.getAuthorizedEndEntityProfileIds(admin).iterator();
	  while(iter.hasNext()){
		Integer next = ((Integer) iter.next());  
		if(this.endEntityAuthorization(admin, next.intValue(), rights)) 
		  returnval.put(profilemap.get(next), next);  
	  }
	  
	  return returnval;
	}     
    
    
	/**
	 * Help function used to check end entity profile authorization.
	 */
	public boolean endEntityAuthorization(Admin admin, int profileid, String rights){
	  boolean returnval = false;
      
	  // TODO FIX
	  if(admin.getAdminInformation().isSpecialUser()){
		return true;
	  }
	  try{
		   returnval = authorizationsession.isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX+Integer.toString(profileid)+rights);
	  }catch(AuthorizationDeniedException e){}

	  return returnval;
	}    

    
    // Private fields.
    private String authcastring = null;
    private String authendentityprofilestring = null;
    private TreeMap authprofilenames = null;
    private TreeMap authcreateprofilenames = null;
	private TreeMap authviewprofilenames = null;
    private Admin admin;
    private IAuthorizationSessionLocal authorizationsession;
    private IRaAdminSessionLocal raadminsession;

}


