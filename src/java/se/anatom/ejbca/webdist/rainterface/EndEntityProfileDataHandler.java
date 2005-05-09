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
 
package se.anatom.ejbca.webdist.rainterface;

import java.util.HashSet;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.EndEntityProfileExistsException;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.LocalRaAdminSessionBean;
import se.anatom.ejbca.webdist.webconfiguration.InformationMemory;

/**
 * A class handling the profile data. It saves and retrieves them currently from a database.
 *
 * @version $Id: EndEntityProfileDataHandler.java,v 1.12 2005-05-09 19:50:38 anatom Exp $
 */
public class EndEntityProfileDataHandler implements java.io.Serializable {

    public static final String EMPTY_PROFILE        = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILE;    
    /** Creates a new instance of EndEntityProfileDataHandler */
    public EndEntityProfileDataHandler(Admin administrator, IRaAdminSessionLocal raadminsession, IAuthorizationSessionLocal authorizationsession, InformationMemory info) {
       this.raadminsession = raadminsession;        
       this.authorizationsession = authorizationsession;
       this.administrator = administrator;          
       this.info = info;
    }
        
       /** Method to add a end entity profile. Throws EndEntityProfileExitsException if profile already exists  */
    public void addEndEntityProfile(String name, EndEntityProfile profile) throws EndEntityProfileExistsException, AuthorizationDeniedException {
      if(authorizedToProfile(profile, true)){
        raadminsession.addEndEntityProfile(administrator, name, profile);
        this.info.endEntityProfilesEdited();
      }else
        throw new AuthorizationDeniedException("Not authorized to add end entity profile");  
    }
      
       /** Method to change a end entity profile. */     
    public void changeEndEntityProfile(String name, EndEntityProfile profile) throws AuthorizationDeniedException{
      if(authorizedToProfile(profile, true)){ 
        raadminsession.changeEndEntityProfile(administrator, name,profile);   
        this.info.endEntityProfilesEdited();
      }else
        throw new AuthorizationDeniedException("Not authorized to edit end entity profile");      
    }
    
    /** Method to remove a end entity profile.*/ 
    public void removeEndEntityProfile(String name) throws AuthorizationDeniedException{
     if(authorizedToProfileName(name, true)){    
        raadminsession.removeEndEntityProfile(administrator, name);
        this.info.endEntityProfilesEdited();
     }else
        throw new AuthorizationDeniedException("Not authorized to remove end entity profile");        
    }
    
    /** Metod to rename a end entity profile */
    public void renameEndEntityProfile(String oldname, String newname) throws EndEntityProfileExistsException, AuthorizationDeniedException{
     if(authorizedToProfileName(oldname, true)){    
       raadminsession.renameEndEntityProfile(administrator, oldname,newname);
       this.info.endEntityProfilesEdited();
     }else
       throw new AuthorizationDeniedException("Not authorized to rename end entity profile");
    }
    

    public void cloneEndEntityProfile(String originalname, String newname) throws EndEntityProfileExistsException, AuthorizationDeniedException{         
      if(authorizedToProfileName(originalname, true)){
        raadminsession.cloneEndEntityProfile(administrator, originalname,newname);
        this.info.endEntityProfilesEdited();
      }else
         throw new AuthorizationDeniedException("Not authorized to clone end entity profile");          
    }    
    
      /** Method to get a reference to a end entity profile.*/ 
    public EndEntityProfile getEndEntityProfile(int id) throws AuthorizationDeniedException{  
      if(!authorizedToProfileId(id, false))
        throw new AuthorizationDeniedException("Not authorized to end entity profile");             
      
      return raadminsession.getEndEntityProfile(administrator, id); 
    }      
          
    public EndEntityProfile getEndEntityProfile(String profilename) throws AuthorizationDeniedException{
     if(!authorizedToProfileName(profilename, false))
        throw new AuthorizationDeniedException("Not authorized to end entity profile");            
         
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
		if(profilename.equals(LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILE))
		  profile = null;
		else    	
          profile = raadminsession.getEndEntityProfile(administrator, profilename);
          
      return authorizedToProfile(profile, editcheck);
    }
     
    
/**
     * Help function that checks if administrator is authorized to edit profile with given name.
     */
    private boolean authorizedToProfileId(int profileid, boolean editcheck){      	    	
      EndEntityProfile profile = null;	
      if(profileid == LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILEID)
        profile = null;
      else  
       profile = raadminsession.getEndEntityProfile(administrator, profileid);
       
      return authorizedToProfile(profile, editcheck);
    }
    
    /**
     * Help function that checks if administrator is authorized to edit profile.
     */    
    private boolean authorizedToProfile(EndEntityProfile profile, boolean editcheck){
      boolean returnval = false;  
      boolean allexists = false;  
      try{  
        if(editcheck)  
          authorizationsession.isAuthorizedNoLog(administrator, "/ra_functionality/edit_end_entity_profiles");
        
        HashSet authorizedcaids = new HashSet(authorizationsession.getAuthorizedCAIds(administrator));
       
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
            String[] availablecas = profile.getValue(EndEntityProfile.AVAILCAS, 0).split(EndEntityProfile.SPLITCHAR);
            allexists = true;
            for(int j=0; j < availablecas.length; j++){
              if(!authorizedcaids.contains( new Integer(availablecas[j]))){
                allexists = false;
              }
            }
          }  
          returnval = allexists;          
        }
      }catch(AuthorizationDeniedException e){}
         
      return returnval;  
    }
    
    private IRaAdminSessionLocal  raadminsession;
    private Admin administrator;
    private IAuthorizationSessionLocal authorizationsession;
    private InformationMemory info;
}
