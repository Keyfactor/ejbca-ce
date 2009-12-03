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
 
package org.ejbca.ui.web.admin.hardtokeninterface;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;

import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;
import org.ejbca.core.model.hardtoken.profiles.EIDProfile;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.web.admin.configuration.InformationMemory;
import org.ejbca.util.Base64PutHashMap;

/**
 * A class handling the hardtoken profile data.
 *
 * @author  TomSelleck
 * @version $Id$
 */
public class HardTokenProfileDataHandler implements Serializable {

    private IHardTokenSessionLocal         hardtokensession; 
    private Admin                          administrator;
    private IAuthorizationSessionLocal     authorizationsession;
    private ICertificateStoreSessionLocal  certificatesession;
    private IUserAdminSessionLocal         useradminsession;
    private ICAAdminSessionLocal           caadminsession; 
    private InformationMemory              info;
    
    /** Creates a new instance of HardTokenProfileDataHandler */
    public HardTokenProfileDataHandler(Admin administrator, IHardTokenSessionLocal hardtokensession, ICertificateStoreSessionLocal certificatesession, IAuthorizationSessionLocal authorizationsession, 
                                       IUserAdminSessionLocal useradminsession, ICAAdminSessionLocal caadminsession, InformationMemory info) {
       this.hardtokensession = hardtokensession;           
       this.authorizationsession = authorizationsession;
       this.certificatesession = certificatesession;
       this.useradminsession = useradminsession;
       this.caadminsession = caadminsession;
       this.administrator = administrator;          
       this.info = info;       
    }
    
       /** Method to add a hard token profile. 
        * 
        * @return false, if the profile have a bad XML encoding.
        * @throws HardTokenProfileExitsException if profile already exists  */
    public boolean addHardTokenProfile(String name, HardTokenProfile profile) throws HardTokenProfileExistsException, AuthorizationDeniedException {
      boolean success = false;
      if(authorizedToProfile(profile, true)){
    	if(checkXMLEncoding(profile)){
          hardtokensession.addHardTokenProfile(administrator, name, profile);
          this.info.hardTokenDataEdited();
          success=true;
    	}  
         
      }else {
        throw new AuthorizationDeniedException("Not authorized to add hard token profile");
      }
      return success;
    }    



	/** Method to change a hard token profile. 
        * 
        * @return false, if the profile have a bad XML encoding.
        * */     
    public boolean changeHardTokenProfile(String name, HardTokenProfile profile) throws AuthorizationDeniedException{
        boolean success = false;
      if(authorizedToProfile(profile, true)){
    	  if(checkXMLEncoding(profile)){   	  
    		  hardtokensession.changeHardTokenProfile(administrator, name,profile);   
    		  this.info.hardTokenDataEdited();
    		  success=true;
    	  } 
      }else {
        throw new AuthorizationDeniedException("Not authorized to edit hard token profile");
      }
      return success;
    }
    
    /** Method to remove a hard token profile, returns true if deletion failed.*/ 
    public boolean removeHardTokenProfile(String name) throws AuthorizationDeniedException{
      boolean returnval = true;  
      
	  int profileid = getHardTokenProfileId(name);
	  
      if(useradminsession.checkForHardTokenProfileId(administrator, profileid)) {
        return true;
      }
	  if(hardtokensession.existsHardTokenProfileInHardTokenIssuer(administrator, profileid)) {
		return true;  
	  }
      if(authorizedToProfileName(name, true)){    
		hardtokensession.removeHardTokenProfile(administrator, name);
		this.info.hardTokenDataEdited();
		returnval = false;
      }else {
        throw new AuthorizationDeniedException("Not authorized to remove hard token profile");
      }
      return returnval;          
    }
    
    /** Metod to rename a hard token profile */
    public void renameHardTokenProfile(String oldname, String newname) throws HardTokenProfileExistsException, AuthorizationDeniedException{
     if(authorizedToProfileName(oldname, true)){    
		hardtokensession.renameHardTokenProfile(administrator, oldname,newname);
	   this.info.hardTokenDataEdited();
     }else {
       throw new AuthorizationDeniedException("Not authorized to rename hard token profile");
     }
    }
    

    public void cloneHardTokenProfile(String originalname, String newname) throws HardTokenProfileExistsException, AuthorizationDeniedException{         
      if(authorizedToProfileName(originalname, false)){
        hardtokensession.cloneHardTokenProfile(administrator, originalname,newname);
        this.info.hardTokenDataEdited();
      }else {
         throw new AuthorizationDeniedException("Not authorized to clone hard token profile");
      }
    }        
    


      /** Method to get a reference to a Hard Token profile.*/ 
    public HardTokenProfile getHardTokenProfile(int id) throws AuthorizationDeniedException{
      if(!authorizedToProfileId(id, false)) {
        throw new AuthorizationDeniedException("Not authorized to hard token profile");            
      }
      return hardtokensession.getHardTokenProfile(administrator, id); 
    }      
          
    public HardTokenProfile getHardTokenProfile(String profilename) throws AuthorizationDeniedException{
     if(!authorizedToProfileName(profilename, false)) {
        throw new AuthorizationDeniedException("Not authorized to hard token profile");            
     }
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
      try{          
        try{
          authorizationsession.isAuthorizedNoLog(administrator, "/super_administrator");
          return true;  
        }catch(AuthorizationDeniedException ade){}
        
        if(editcheck)        
          authorizationsession.isAuthorizedNoLog(administrator, "/hardtoken_functionality/edit_hardtoken_profiles");
  	      HashSet authorizedcertprofiles = new HashSet(certificatesession.getAuthorizedCertificateProfileIds(administrator, SecConst.CERTTYPE_HARDTOKEN));
  	      HashSet authorizedcaids = new HashSet(caadminsession.getAvailableCAs(administrator));
		  if(profile instanceof EIDProfile){		  	
		  	if(authorizedcertprofiles.containsAll(((EIDProfile) profile).getAllCertificateProfileIds()) &&
		  	   authorizedcaids.containsAll(((EIDProfile) profile).getAllCAIds())){
		  	  returnval = true;			  	   
		  	}		  	
		  }else{
		  	//Implement for other profile types
		  }		   		  	   	  	  
        
      }catch(AuthorizationDeniedException e){}
          
      return returnval;  
    }    
   
    /**
     * Method that test to XML encode and decode a profile.
     * @param profile 
     * @return false if something went wrong in the encoding process.
     */
    private boolean checkXMLEncoding(HardTokenProfile profile) {
        boolean success = false;
        try{
            
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            
            // We must base64 encode string for UTF safety
            HashMap a = new Base64PutHashMap();
            a.putAll((HashMap)profile.saveData());
            java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
            encoder.writeObject(a);
            encoder.close();
            String data = baos.toString("UTF8");
            java.beans.XMLDecoder decoder = new java.beans.XMLDecoder(
                        new java.io.ByteArrayInputStream(data.getBytes("UTF8")));
            decoder.readObject();
            decoder.close();
            
            success = true;
        } catch (Exception e) {
            success = false;  
        }

		return success;
	}
}
