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
import java.util.HashSet;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.ca.store.CertificateDataBean;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.hardtoken.HardTokenProfileExistsException;
import se.anatom.ejbca.hardtoken.IHardTokenSessionLocal;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.EIDProfile;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionLocal;
import se.anatom.ejbca.webdist.webconfiguration.InformationMemory;
/**
 * A class handling the hardtoken profile data.
 *
 * @author  TomSelleck
 */
public class HardTokenProfileDataHandler implements Serializable {

    
    
    /** Creates a new instance of HardTokenProfileDataHandler */
    public HardTokenProfileDataHandler(Admin administrator, IHardTokenSessionLocal hardtokensession, ICertificateStoreSessionLocal certificatesession, IAuthorizationSessionLocal authorizationsession, 
                                       IUserAdminSessionLocal useradminsession, InformationMemory info) {
       this.hardtokensession = hardtokensession;           
       this.authorizationsession = authorizationsession;
       this.certificatesession = certificatesession;
       this.useradminsession = useradminsession;
       this.administrator = administrator;          
       this.info = info;       
    }
    
       /** Method to add a hard token profile. Throws HardTokenProfileExitsException if profile already exists  */
    public void addHardTokenProfile(String name, HardTokenProfile profile) throws HardTokenProfileExistsException, AuthorizationDeniedException {
      if(authorizedToProfile(profile, true)){
        hardtokensession.addHardTokenProfile(administrator, name, profile);
        this.info.hardTokenDataEdited();
      }else
        throw new AuthorizationDeniedException("Not authorized to add hard token profile");  
    }    

       /** Method to change a hard token profile. */     
    public void changeHardTokenProfile(String name, HardTokenProfile profile) throws AuthorizationDeniedException{
      if(authorizedToProfile(profile, true)){ 
        hardtokensession.changeHardTokenProfile(administrator, name,profile);   
		this.info.hardTokenDataEdited();
      }else
        throw new AuthorizationDeniedException("Not authorized to edit hard token profile");      
    }
    
    /** Method to remove a hard token profile, returns true if deletion failed.*/ 
    public boolean removeHardTokenProfile(String name) throws AuthorizationDeniedException{
      boolean returnval = true;  
      
      if(useradminsession.checkForHardTokenProfileId(administrator, getHardTokenProfileId(name)))
        return true;
        
      if(authorizedToProfileName(name, true)){    
		hardtokensession.removeHardTokenProfile(administrator, name);
		this.info.hardTokenDataEdited();
		returnval = false;
      }else
        throw new AuthorizationDeniedException("Not authorized to remove hard token profile");
        
      return returnval;          
    }
    
    /** Metod to rename a hard token profile */
    public void renameHardTokenProfile(String oldname, String newname) throws HardTokenProfileExistsException, AuthorizationDeniedException{
     if(authorizedToProfileName(oldname, true)){    
		hardtokensession.renameHardTokenProfile(administrator, oldname,newname);
	   this.info.hardTokenDataEdited();
     }else
       throw new AuthorizationDeniedException("Not authorized to rename hard token profile");
    }
    

    public void cloneHardTokenProfile(String originalname, String newname) throws HardTokenProfileExistsException, AuthorizationDeniedException{         
      if(authorizedToProfileName(originalname, false)){
        hardtokensession.cloneHardTokenProfile(administrator, originalname,newname);
        this.info.hardTokenDataEdited();
      }else
         throw new AuthorizationDeniedException("Not authorized to clone hard token profile");          
    }        
    


      /** Method to get a reference to a Hard Token profile.*/ 
    public HardTokenProfile getHardTokenProfile(int id) throws AuthorizationDeniedException{
      if(!authorizedToProfileId(id, false))
        throw new AuthorizationDeniedException("Not authorized to hard token profile");            
      
      return hardtokensession.getHardTokenProfile(administrator, id); 
    }      
          
    public HardTokenProfile getHardTokenProfile(String profilename) throws AuthorizationDeniedException{
     if(!authorizedToProfileName(profilename, false))
        throw new AuthorizationDeniedException("Not authorized to hard token profile");            
         
      return hardtokensession.getHardTokenProfile(administrator, profilename);
    }
   
      
    public int getHardTokenProfileId(String profilename){
      return hardtokensession.getHardTokenProfileId(administrator, profilename);  
    }
    
    
    /**
     * Help function that checks if administrator is authorized to edit profile with given name.
     */
    private boolean authorizedToProfileName(String profilename, boolean editcheck){
		HardTokenProfile profile = hardtokensession.getHardTokenProfile(administrator, profilename);
      return authorizedToProfile(profile, editcheck);
    }
     
    
    /**
     * Help function that checks if administrator is authorized to edit profile with given name.
     */
    private boolean authorizedToProfileId(int profileid, boolean editcheck){
      HardTokenProfile profile = hardtokensession.getHardTokenProfile(administrator, profileid);
      return authorizedToProfile(profile, editcheck);
    }
    
    /**
     * Help function that checks if administrator is authorized to edit profile.
     */    
    private boolean authorizedToProfile(HardTokenProfile profile, boolean editcheck){
      boolean returnval = false;  
      boolean allexists = false;  
      try{          
        try{
          authorizationsession.isAuthorizedNoLog(administrator, "/super_administrator");
          return true;  
        }catch(AuthorizationDeniedException ade){}
        
        if(editcheck)        
          authorizationsession.isAuthorizedNoLog(administrator, "/hardtoken_functionality/edit_hardtoken_profiles");
          
        
  	      HashSet authorizedcertprofiles = new HashSet(certificatesession.getAuthorizedCertificateProfileIds(administrator, CertificateDataBean.CERTTYPE_HARDTOKEN));	  	   	  
        		  
		  if(profile instanceof EIDProfile){		  	
		  	if(authorizedcertprofiles.containsAll(((EIDProfile) profile).getAllCertificateProfileIds())){
		  	  returnval = true;			  	   
		  	}		  	
		  }else{
		  	//Implement for other profile types
		  }		   		  	   	  	  
        
      }catch(AuthorizationDeniedException e){}
    
      
      return returnval;  
    }    
   
    private IHardTokenSessionLocal         hardtokensession; 
    private Admin                          administrator;
    private IAuthorizationSessionLocal     authorizationsession;
    private ICertificateStoreSessionLocal  certificatesession;
    private IUserAdminSessionLocal         useradminsession;
    private InformationMemory              info;
}
