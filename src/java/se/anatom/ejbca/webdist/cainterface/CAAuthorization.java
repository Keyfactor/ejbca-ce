package se.anatom.ejbca.webdist.cainterface;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.log.Admin;

/**
 * A class that looks up the which CA:s and certificate profiles the administrator is authorized to view.
 * 
 * @version $Id: CAAuthorization.java,v 1.1 2003-09-04 09:46:43 herrvendil Exp $
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
    
    
    
    public TreeMap getAuthorizedEndEntityCertificateProfileNames(){
      if(profilenamesendentity==null){
        profilenamesendentity = new TreeMap();  
        Iterator iter = certificatestoresession.getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_ENDENTITY).iterator();      
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
    
    public TreeMap getAuthorizedCertificateProfileNames(){
      if(allprofilenames==null){
        allprofilenames = new TreeMap();  
        Iterator iter = certificatestoresession.getAuthorizedCertificateProfileIds(admin, 0).iterator();      
        HashMap idtonamemap = certificatestoresession.getCertificateProfileIdToNameMap(admin);
        while(iter.hasNext()){
          Integer id = (Integer) iter.next();
          allprofilenames.put(idtonamemap.get(id),id);
        }
      }
      return allprofilenames;  
    }    
        
    
    
    public TreeMap getCANames(){
      System.out.println("CAAuthorization : >getCANames ");  
      if(canames==null){
        System.out.println("CAAuthorization : getCANames , not null");    
        canames = new TreeMap();        
        HashMap idtonamemap = this.caadminsession.getCAIdToNameMap(admin);
        Iterator iter = getAuthorizedCAIds().iterator();
        while(iter.hasNext()){          
          Integer id = (Integer) iter.next();
          System.out.println("CAAuthorization : getCANames , found " + idtonamemap.get(id));
          canames.put(idtonamemap.get(id),id);
        }        
      }
      System.out.println("CAAuthorization : <getCANames ");  
      return canames;  
    }
    
    
    public void clear(){
      authcas=null;
      profilenamesendentity = null;
      profilenamessubca = null;
      profilenamesrootca = null;
      allprofilenames = null;
      canames=null;
    }    
    
    // Private fields.
    private Collection authcas = null;
    private TreeMap profilenamesendentity = null;
    private TreeMap profilenamessubca = null;
    private TreeMap profilenamesrootca = null;
    private TreeMap canames = null;
    private TreeMap allprofilenames = null;
    private Admin admin;
    private ICAAdminSessionLocal caadminsession;
    private IAuthorizationSessionLocal authorizationsession;
    private ICertificateStoreSessionLocal certificatestoresession;

}


