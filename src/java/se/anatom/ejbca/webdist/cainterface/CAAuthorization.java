package se.anatom.ejbca.webdist.cainterface;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.log.Admin;

/**
 * A class that looks up the which CA:s and certificate profiles the administrator is authorized to view.
 * 
 * @version $Id: CAAuthorization.java,v 1.4 2003-12-05 14:50:27 herrvendil Exp $
 */
public class CAAuthorization implements Serializable {
    
  
    
    /** Creates a new instance of CAAuthorization. */
    public CAAuthorization(Admin admin,  
                           ICAAdminSessionLocal caadminsession,
                           ICertificateStoreSessionLocal certificatestoresession, 
                           IAuthorizationSessionLocal authorizationsession) {
      this.admin=admin;
      this.caadminsession=caadminsession;      
      this.certificatestoresession=certificatestoresession;
      this.authorizationsession=authorizationsession;
    }

    
    
    /**
     * Methos returning a Collection of authorizaed CA ids (Integer).
     *
     */
    public Collection getAuthorizedCAIds() {         
      if(authcas ==null || authcas.size() == 0){
        authcas = this.authorizationsession.getAuthorizedCAIds(admin);                  
      }
      
      return authcas;
    } 
    
    
    
    public TreeMap getAuthorizedEndEntityCertificateProfileNames(boolean usehardtokenprofiles){
      if(profilenamesendentity==null){
        profilenamesendentity = new TreeMap();  
        Iterator iter = null;
        if(usehardtokenprofiles)         
          iter = certificatestoresession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_HARDTOKEN).iterator();
        else         
		  iter = certificatestoresession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_ENDENTITY).iterator();
        HashMap idtonamemap = certificatestoresession.getCertificateProfileIdToNameMap(admin);
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
        Iterator iter = certificatestoresession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_SUBCA).iterator();      
        HashMap idtonamemap = certificatestoresession.getCertificateProfileIdToNameMap(admin);
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
        Iterator iter = certificatestoresession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_ROOTCA).iterator();      
        HashMap idtonamemap = certificatestoresession.getCertificateProfileIdToNameMap(admin);
        while(iter.hasNext()){
          Integer id = (Integer) iter.next();
          profilenamesrootca.put(idtonamemap.get(id),id);
        }
      }
      return profilenamesrootca;  
    }
    
    public TreeMap getEditCertificateProfileNames(){
      if(allprofilenames==null){
      	// check if administrator
      	boolean superadministrator = false;
		try{
		  superadministrator = authorizationsession.isAuthorizedNoLog(admin, "/super_administrator");
		}catch(AuthorizationDeniedException ade){}
      	
        allprofilenames = new TreeMap();  
        Iterator iter = certificatestoresession.getAuthorizedCertificateProfileIds(admin, 0).iterator();      
        HashMap idtonamemap = certificatestoresession.getCertificateProfileIdToNameMap(admin);
        while(iter.hasNext()){
        
          Integer id = (Integer) iter.next();
          CertificateProfile certprofile = certificatestoresession.getCertificateProfile(admin,id.intValue());
 
          // If not superadministrator, then should only end entity profiles be added.
          if(superadministrator || certprofile.getType() == CertificateProfile.TYPE_ENDENTITY){                      
            // if default profiles, add fixed to name.
            if(id.intValue() <= SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY || 
               (!superadministrator && certprofile.isApplicableToAnyCA()))
			  allprofilenames.put(idtonamemap.get(id) + " (FIXED)",id);   
            else
		      allprofilenames.put(idtonamemap.get(id),id);          
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
	  if(allcanames==null){        
		allcanames = new TreeMap();        
		HashMap idtonamemap = this.caadminsession.getCAIdToNameMap(admin);
		Iterator iter = idtonamemap.keySet().iterator();
		while(iter.hasNext()){          
		  Integer id = (Integer) iter.next();          
		  allcanames.put(idtonamemap.get(id),id);
		}        
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
    
    // Private fields.
    private Collection authcas = null;
    private TreeMap profilenamesendentity = null;
    private TreeMap profilenamessubca = null;
    private TreeMap profilenamesrootca = null;
    private TreeMap canames = null;
	private TreeMap allcanames = null;
    private TreeMap allprofilenames = null;
    private Admin admin;
    private ICAAdminSessionLocal caadminsession;
    private IAuthorizationSessionLocal authorizationsession;
    private ICertificateStoreSessionLocal certificatestoresession;

}


