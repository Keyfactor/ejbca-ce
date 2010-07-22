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
 
package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;

import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.web.admin.configuration.InformationMemory;

/**
 * A class handling the certificate type data. It saves and retrieves them currently from a database.
 *
 * @author  TomSelleck
 * @version $Id$
 */
public class CertificateProfileDataHandler implements Serializable {
	   
    private ICertificateStoreSessionLocal  certificatestoresession; 
    private Admin                          administrator;
    private IAuthorizationSessionLocal     authorizationsession;
    private InformationMemory              info;
    private ICAAdminSessionLocal           caadminsession;

    public static final int FIXED_CERTIFICATEPROFILE_BOUNDRY        = SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY;
    /** Creates a new instance of CertificateProfileDataHandler */
    public CertificateProfileDataHandler(Admin administrator, ICertificateStoreSessionLocal certificatesession, IAuthorizationSessionLocal authorizationsession, ICAAdminSessionLocal caadminsession, InformationMemory info) {
       this.certificatestoresession = certificatesession;           
       this.authorizationsession = authorizationsession;
       this.caadminsession = caadminsession;
       this.administrator = administrator;          
       this.info = info;       
    }
    
       /** Method to add a certificate profile. Throws CertificateProfileExitsException if profile already exists  */
    public void addCertificateProfile(String name, CertificateProfile profile) throws CertificateProfileExistsException, AuthorizationDeniedException {
      if(authorizedToProfile(profile, true)){
        certificatestoresession.addCertificateProfile(administrator, name, profile);
        this.info.certificateProfilesEdited();
      }else {
        throw new AuthorizationDeniedException("Not authorized to add certificate profile");
      }
    }    

       /** Method to change a certificate profile. */     
    public void changeCertificateProfile(String name, CertificateProfile profile) throws AuthorizationDeniedException{
      if(authorizedToProfile(profile, true)){ 
        certificatestoresession.changeCertificateProfile(administrator, name,profile);   
        this.info.certificateProfilesEdited();
      }else {
        throw new AuthorizationDeniedException("Not authorized to edit certificate profile");
      }
    }
    
    /** Method to remove a end entity profile.*/ 
    public void removeCertificateProfile(String name) throws AuthorizationDeniedException{
     if(authorizedToProfileName(name, true)){    
        certificatestoresession.removeCertificateProfile(administrator, name);
        this.info.certificateProfilesEdited();
     }else {
        throw new AuthorizationDeniedException("Not authorized to remove certificate profile");
     }
    }
    
    /** Metod to rename a end entity profile */
    public void renameCertificateProfile(String oldname, String newname) throws CertificateProfileExistsException, AuthorizationDeniedException{
     if(authorizedToProfileName(oldname, true)){    
       certificatestoresession.renameCertificateProfile(administrator, oldname,newname);
       this.info.certificateProfilesEdited();
     }else {
       throw new AuthorizationDeniedException("Not authorized to rename certificate profile");
     }
    }
    

    public void cloneCertificateProfile(String originalname, String newname) throws CertificateProfileExistsException, AuthorizationDeniedException{         
      if(authorizedToProfileName(originalname, false)){
        certificatestoresession.cloneCertificateProfile(administrator, originalname,newname, caadminsession.getAvailableCAs(administrator));
        this.info.certificateProfilesEdited();
      }else {
         throw new AuthorizationDeniedException("Not authorized to clone certificate profile");
      }
    }        
    


      /** Method to get a reference to a end entity profile.*/ 
    public CertificateProfile getCertificateProfile(int id) throws AuthorizationDeniedException{
      if(!authorizedToProfileId(id, false)) {
        throw new AuthorizationDeniedException("Not authorized to certificate profile");
      }
      return certificatestoresession.getCertificateProfile(administrator, id); 
    }      
          
    public CertificateProfile getCertificateProfile(String profilename) throws AuthorizationDeniedException{
     if(!authorizedToProfileName(profilename, false)) {
        throw new AuthorizationDeniedException("Not authorized to certificate profile");
     }   
     return certificatestoresession.getCertificateProfile(administrator, profilename);
    }
   
      
    public int getCertificateProfileId(String profilename){
      return certificatestoresession.getCertificateProfileId(administrator, profilename);  
    }
    
    
    /**
     * Help function that checks if administrator is authorized to edit profile with given name.
     */
    private boolean authorizedToProfileName(String profilename, boolean editcheck){
      CertificateProfile profile = certificatestoresession.getCertificateProfile(administrator, profilename);
      return authorizedToProfile(profile, editcheck);
    }
     
    
    /**
     * Help function that checks if administrator is authorized to edit profile with given name.
     */
    private boolean authorizedToProfileId(int profileid, boolean editcheck){
      CertificateProfile profile = certificatestoresession.getCertificateProfile(administrator, profileid);
      return authorizedToProfile(profile, editcheck);
    }
    
    /**
     * Help function that checks if administrator is authorized to edit profile.
     */    
    private boolean authorizedToProfile(CertificateProfile profile, boolean editcheck){
      boolean returnval = false;  
      try{  
    	  boolean issuperadministrator = false;
    	  try {
    		  issuperadministrator = authorizationsession.isAuthorizedNoLog(administrator, "/super_administrator");  
    	  } catch(AuthorizationDeniedException ade) {}

    	  if (editcheck) {        
    		  authorizationsession.isAuthorizedNoLog(administrator, "/ca_functionality/edit_certificate_profiles");
    	  }
    	  HashSet authorizedcaids = new HashSet(caadminsession.getAvailableCAs(administrator));

    	  if(profile != null){       
    		  if(!issuperadministrator && profile.getType() != CertificateProfile.TYPE_ENDENTITY) {
    			  returnval = false;
    		  } else {          		      
    			  Collection availablecas = profile.getAvailableCAs();
    			  if (availablecas.contains(new Integer(CertificateProfile.ANYCA))){
    				  if (issuperadministrator && editcheck) {
    					  returnval = true;  
    				  }
    				  if (!editcheck) {
    					  returnval = true;
    				  }
    			  } else {
    				  returnval = authorizedcaids.containsAll(availablecas);
    			  }
    		  }                           
    	  }
      }catch (AuthorizationDeniedException e) {}
         
      return returnval;  
    }    
}
