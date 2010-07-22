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
 
package org.ejbca.ui.web.admin.rainterface;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.LocalRaAdminSessionBean;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.ui.web.admin.configuration.InformationMemory;

/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @version $Id$
 */
public class EndEntityProfileDataHandler implements java.io.Serializable {

    private static final Logger log = Logger.getLogger(EndEntityProfileDataHandler.class);    

    private IRaAdminSessionLocal  raadminsession;
    private Admin administrator;
    private IAuthorizationSessionLocal authorizationsession;
    private ICAAdminSessionLocal caadminsession;
    private InformationMemory info;

    public static final String EMPTY_PROFILE        = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILE;    
    /** Creates a new instance of EndEntityProfileDataHandler */
    public EndEntityProfileDataHandler(Admin administrator, IRaAdminSessionLocal raadminsession, IAuthorizationSessionLocal authorizationsession, ICAAdminSessionLocal caadminsession, InformationMemory info) {
       this.raadminsession = raadminsession;        
       this.authorizationsession = authorizationsession;
       this.caadminsession = caadminsession;
       this.administrator = administrator;          
       this.info = info;
    }
        
       /** Method to add a end entity profile. Throws EndEntityProfileExitsException if profile already exists  */
    public void addEndEntityProfile(String name, EndEntityProfile profile) throws EndEntityProfileExistsException, AuthorizationDeniedException {
      if(authorizedToProfile(profile, true)){
        raadminsession.addEndEntityProfile(administrator, name, profile);
        this.info.endEntityProfilesEdited();
      }else {
        throw new AuthorizationDeniedException("Not authorized to add end entity profile");
      }
    }
      
       /** Method to change a end entity profile. */     
    public void changeEndEntityProfile(String name, EndEntityProfile profile) throws AuthorizationDeniedException{
      if(authorizedToProfile(profile, true)){ 
        raadminsession.changeEndEntityProfile(administrator, name,profile);   
        this.info.endEntityProfilesEdited();
      }else {
        throw new AuthorizationDeniedException("Not authorized to edit end entity profile");
      }
    }
    
    /** Method to remove a end entity profile.*/ 
    public void removeEndEntityProfile(String name) throws AuthorizationDeniedException{
     if(authorizedToProfileName(name, true)){    
        raadminsession.removeEndEntityProfile(administrator, name);
        this.info.endEntityProfilesEdited();
     }else {
        throw new AuthorizationDeniedException("Not authorized to remove end entity profile");
     }
    }
    
    /** Metod to rename a end entity profile */
    public void renameEndEntityProfile(String oldname, String newname) throws EndEntityProfileExistsException, AuthorizationDeniedException{
     if(authorizedToProfileName(oldname, true)){    
       raadminsession.renameEndEntityProfile(administrator, oldname,newname);
       this.info.endEntityProfilesEdited();
     }else {
       throw new AuthorizationDeniedException("Not authorized to rename end entity profile");
     }
    }
    

    public void cloneEndEntityProfile(String originalname, String newname) throws EndEntityProfileExistsException, AuthorizationDeniedException{         
      if(authorizedToProfileName(originalname, true)){
        raadminsession.cloneEndEntityProfile(administrator, originalname,newname);
        this.info.endEntityProfilesEdited();
      }else {
         throw new AuthorizationDeniedException("Not authorized to clone end entity profile");
      }
    }    
    
      /** Method to get a reference to a end entity profile.*/ 
    public EndEntityProfile getEndEntityProfile(int id) throws AuthorizationDeniedException{  
      if(!authorizedToProfileId(id, false)) {
        throw new AuthorizationDeniedException("Not authorized to end entity profile: "+id);             
      }
      return raadminsession.getEndEntityProfile(administrator, id); 
    }      
          
    public EndEntityProfile getEndEntityProfile(String profilename) throws AuthorizationDeniedException{
     if(!authorizedToProfileName(profilename, false)) {
        throw new AuthorizationDeniedException("Not authorized to end entity profile: "+profilename);            
     }
      return raadminsession.getEndEntityProfile(administrator, profilename);
    }
   
      
    public int getEndEntityProfileId(String profilename){
      return raadminsession.getEndEntityProfileId(administrator, profilename);  
    }
       

    
    /**
     * Help function that checks if administrator is authorized to edit profile with given name.
     */
    private boolean authorizedToProfileName(String profilename, boolean editcheck){
       EndEntityProfile profile = null;	
		if(profilename.equals(LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILE)) {
		  profile = null;
		} else {    	
          profile = raadminsession.getEndEntityProfile(administrator, profilename);
		}
      return authorizedToProfile(profile, editcheck);
    }
     
    
/**
     * Help function that checks if administrator is authorized to edit profile with given name.
     */
    private boolean authorizedToProfileId(int profileid, boolean editcheck){      	    	
      EndEntityProfile profile = null;	
      if(profileid == LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILEID) {
        profile = null;
      } else {  
       profile = raadminsession.getEndEntityProfile(administrator, profileid);
      }
      return authorizedToProfile(profile, editcheck);
    }
    
    /**
     * Help function that checks if administrator is authorized to edit profile.
     */    
    private boolean authorizedToProfile(EndEntityProfile profile, boolean editcheck){
      boolean returnval = false;  
      boolean allexists = false;  
      try{  
        if(editcheck) {
          authorizationsession.isAuthorizedNoLog(administrator, "/ra_functionality/edit_end_entity_profiles");
        }
        HashSet authorizedcaids = new HashSet(authorizationsession.getAuthorizedCAIds(administrator, caadminsession.getAvailableCAs()));
       if(profile == null && editcheck){
			authorizationsession.isAuthorizedNoLog(administrator, "/super_administrator");
       }
       if(profile == null){  
           returnval = true;                                           
       }else{
          String availablecasstring = profile.getValue(EndEntityProfile.AVAILCAS, 0);   
          if(availablecasstring == null || availablecasstring.equals("")){
            allexists = true;  
          }else{
        	  // Go through all available CAs in the profile and check that the administrator is authorized to all CAs specified in the profile
        	  // If ALLCAS is selected in the end entity profile, we must check that the administrator is authorized to all CAs in the system.
        	  String[] availablecas = profile.getValue(EndEntityProfile.AVAILCAS, 0).split(EndEntityProfile.SPLITCHAR);
    		  // If availablecas contains SecConst ALLCAS, change availablecas to be a list of all CAs
        	  if (ArrayUtils.contains(availablecas, String.valueOf(SecConst.ALLCAS))) {
            	  Collection allcaids = caadminsession.getAvailableCAs();
            	  if (log.isDebugEnabled()) {
            		  log.debug("Available CAs in end entity profile contains ALLCAS, lising all CAs in the system instead. There are "+allcaids.size()+" CAs in the system");
            	  }
            	  availablecas = new String[allcaids.size()];
            	  int index = 0;
            	  for (Iterator iterator = allcaids.iterator(); iterator.hasNext();) {
            		  Integer id = (Integer) iterator.next();
            		  availablecas[index++] = id.toString();
            	  }
        	  }
        	  allexists = true;
        	  for(int j=0; j < availablecas.length; j++){
        		  Integer caid = new Integer(availablecas[j]);
        		  if(!authorizedcaids.contains(caid)){
        			  log.debug("Not authorized to profile because admin is not authorized to CA "+caid);
        			  allexists = false;            		              		  
        		  }
        	  }
          }  
          returnval = allexists;          
        }
      }catch(AuthorizationDeniedException e){}
         
      return returnval;  
    }
}
