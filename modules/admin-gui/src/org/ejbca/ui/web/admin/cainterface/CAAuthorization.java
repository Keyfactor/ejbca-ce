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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;

import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.log.Admin;

/**
 * A class that looks up the which CA:s and certificate profiles the administrator is authorized to view.
 * 
 * @version $Id$
 */
public class CAAuthorization implements Serializable {

    private Collection authcas = null;
    private TreeMap profilenamesendentity = null;
    private TreeMap profilenamessubca = null;
    private TreeMap profilenamesrootca = null;
    private TreeMap canames = null;
	private TreeMap allcanames = null;
    private TreeMap allprofilenames = null;
    private Admin admin;
    private CAAdminSession caadminsession;
    private AuthorizationSession authorizationsession;
    private CertificateProfileSession certificateProfileSession;
    
    /** Creates a new instance of CAAuthorization. */
    public CAAuthorization(Admin admin,  
                           CAAdminSession caadminsession,
                           AuthorizationSession authorizationsession, CertificateProfileSession certificateProfileSession) {
      this.admin=admin;
      this.caadminsession=caadminsession;      
      this.authorizationsession=authorizationsession;
        this.certificateProfileSession = certificateProfileSession;
    }

    /**
     * Method returning a Collection of authorized CA id's (Integer).
     *
     */
    public Collection<Integer> getAuthorizedCAIds() {         
    	if(authcas == null || authcas.size() == 0){
    		authcas = caadminsession.getAvailableCAs(admin);
    	}
    	return authcas;
    } 
    
    
    
    public TreeMap getAuthorizedEndEntityCertificateProfileNames(boolean usehardtokenprofiles){
      if(profilenamesendentity==null){
        profilenamesendentity = new TreeMap();  
        Iterator iter = null;
        if(usehardtokenprofiles) {         
          iter = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_HARDTOKEN, getAuthorizedCAIds()).iterator();
        } else {         
		  iter = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_ENDENTITY, getAuthorizedCAIds()).iterator();
        }
        HashMap idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap(admin);
        while(iter.hasNext()){
          Integer id = (Integer) iter.next();
          profilenamesendentity.put(idtonamemap.get(id),id);
        }
      }
      return profilenamesendentity;  
    }
            
    public TreeMap getAuthorizedSubCACertificateProfileNames(){
      if(profilenamessubca==null){
        profilenamessubca = new TreeMap();  
        Iterator iter = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_SUBCA, getAuthorizedCAIds()).iterator();      
        HashMap idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap(admin);
        while(iter.hasNext()){
          Integer id = (Integer) iter.next();
          profilenamessubca.put(idtonamemap.get(id),id);
        }
      }
      return profilenamessubca;  
    }
    
    
    public TreeMap getAuthorizedRootCACertificateProfileNames(){
      if(profilenamesrootca==null){
        profilenamesrootca = new TreeMap();  
        Iterator iter = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_ROOTCA, getAuthorizedCAIds()).iterator();      
        HashMap idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap(admin);
        while(iter.hasNext()){
          Integer id = (Integer) iter.next();
          profilenamesrootca.put(idtonamemap.get(id),id);
        }
      }
      return profilenamesrootca;  
    }
    
    public TreeMap getEditCertificateProfileNames(boolean includefixedhardtokenprofiles){
      if(allprofilenames==null){
      	// check if administrator
      	boolean superadministrator = false;
		try{
		  superadministrator = authorizationsession.isAuthorizedNoLog(admin, "/super_administrator");
		}catch(AuthorizationDeniedException ade){}
      	
        allprofilenames = new TreeMap();
        Iterator iter= null;  
        if(includefixedhardtokenprofiles){
          iter = certificateProfileSession.getAuthorizedCertificateProfileIds(admin, 0, getAuthorizedCAIds()).iterator();
        }else{
          ArrayList certprofiles = new ArrayList();
		  certprofiles.addAll(certificateProfileSession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_ENDENTITY, getAuthorizedCAIds()));
		  certprofiles.addAll(certificateProfileSession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_ROOTCA, getAuthorizedCAIds()));
		  certprofiles.addAll(certificateProfileSession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_SUBCA, getAuthorizedCAIds()));
		  iter = certprofiles.iterator();
        }
        HashMap idtonamemap = certificateProfileSession.getCertificateProfileIdToNameMap(admin);
        while(iter.hasNext()){
        
          Integer id = (Integer) iter.next();
          CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(admin,id.intValue());
 
          // If not superadministrator, then should only end entity profiles be added.
          if(superadministrator || certprofile.getType() == CertificateProfile.TYPE_ENDENTITY){                      
            // if default profiles, add fixed to name.
            if(id.intValue() <= SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY || (!superadministrator && certprofile.isApplicableToAnyCA())) {
			  allprofilenames.put(idtonamemap.get(id) + " (FIXED)",id);   
            } else {
		      allprofilenames.put(idtonamemap.get(id),id);
            }
          }
        }  
      }
      return allprofilenames;  
    }    
        
    
    
    public TreeMap getCANames(){        
      if(canames==null){        
        canames = new TreeMap();        
        HashMap idtonamemap = this.caadminsession.getCAIdToNameMap(admin);
        Iterator iter = getAuthorizedCAIds().iterator();
        while(iter.hasNext()){          
          Integer id = (Integer) iter.next();          
          canames.put(idtonamemap.get(id),id);
        }        
      }       
      return canames;  
    }
    
	public TreeMap getAllCANames(){              
		allcanames = new TreeMap();        
		HashMap idtonamemap = this.caadminsession.getCAIdToNameMap(admin);
		Iterator iter = idtonamemap.keySet().iterator();
		while(iter.hasNext()){          
		  Integer id = (Integer) iter.next();          
		  allcanames.put(idtonamemap.get(id),id);
		}        
       
	  return allcanames;  
	}    
    public void clear(){
      authcas=null;
      profilenamesendentity = null;
      profilenamessubca = null;
      profilenamesrootca = null;
      allprofilenames = null;
      canames=null;
      allcanames=null;
    }    
}
