/*
 * InformationMemory.java
 *
 * Created on den 14 juli 2003, 14:05
 */

package se.anatom.ejbca.webdist.webconfiguration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.RAAuthorization;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.webdist.cainterface.CAAuthorization;
import se.anatom.ejbca.webdist.cainterface.CertificateProfileNameProxy;
import se.anatom.ejbca.webdist.loginterface.LogAuthorization;
import se.anatom.ejbca.webdist.rainterface.EndEntityProfileNameProxy;


/**
 * A class used to improve performance by proxying authorization information about the administrator.
 * It should be used in all jsp interface bean classes. 
 * @author  TomSelleck
 */
public class InformationMemory {
    
    /** Creates a new instance of ProfileNameProxy */
    public InformationMemory(Admin administrator,
                             ICAAdminSessionLocal  caadminsession,
                             IRaAdminSessionLocal raadminsession, 
                             IAuthorizationSessionLocal authorizationsession,
                             ISignSessionLocal signsession,
                             ICertificateStoreSessionLocal certificatestoresession,
                             GlobalConfiguration globalconfiguration){
      this.caadminsession = caadminsession;                           
      this.administrator = administrator;
      this.raadminsession = raadminsession;
      this.authorizationsession = authorizationsession;
      this.signsession = signsession;
      this.certificatestoresession = certificatestoresession;
      this.globalconfiguration = globalconfiguration;
      
      this.raauthorization = new RAAuthorization(administrator, raadminsession, authorizationsession);
      this.caauthorization = new CAAuthorization(administrator, caadminsession, certificatestoresession, authorizationsession);
      this.logauthorization = new LogAuthorization(administrator, authorizationsession);
    }
    
    
    /**
     * Returns a Map of end entity profile id (Integer) -> end entity profile name (String).
     */
    public HashMap getEndEntityProfileIdToNameMap(){
      if(endentityprofileidtonamemap == null){
        endentityprofileidtonamemap = raadminsession.getEndEntityProfileIdToNameMap(administrator);  
      }
      
      return endentityprofileidtonamemap;
    }
    

    /**
     * Returns a Map of certificate profile id (Integer) -> certificate name (String).
     */
    public HashMap getCertificateProfileIdToNameMap(){
      if(certificateprofileidtonamemap == null){
        certificateprofileidtonamemap = this.certificatestoresession.getCertificateProfileIdToNameMap(administrator); 
      }
      
      return certificateprofileidtonamemap;
    }    

    /**
     * Returns a Map of CA id (Integer) -> CA name (String).
     */
    public HashMap getCAIdToNameMap(){
      if(caidtonamemap == null){
        caidtonamemap = caadminsession.getCAIdToNameMap(administrator);
      }
      
      return caidtonamemap;
    }    
    
    /**
     * Returns authorized end entity profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap getAuthorizedEndEntityProfileNames(){
      return this.raauthorization.getAuthorizedEndEntityProfileNames();   
    }
    
    /**
     * Returns authorized end entity certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap getAuthorizedEndEntityCertificateProfileNames(){
      return this.caauthorization.getAuthorizedEndEntityCertificateProfileNames();   
    }    

    /**
     * Returns authorized sub CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap getAuthorizedSubCACertificateProfileNames(){
      return this.caauthorization.getAuthorizedSubCACertificateProfileNames();   
    } 
    
    /**
     * Returns authorized root CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap getAuthorizedRootCACertificateProfileNames(){
      return this.caauthorization.getAuthorizedRootCACertificateProfileNames();   
    } 
    
    /**
     * Returns all authorized certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap getAuthorizedCertificateProfileNames(){
      return this.caauthorization.getAuthorizedCertificateProfileNames();   
    }     
    
    /**
     * Returns a CA names as a treemap of name (String) -> id (Integer).
     */
    public TreeMap getCANames(){
      return this.caauthorization.getCANames();   
    }     
 
    /**
     * Returns string used in view log queries.
     */
    public String getViewLogQueryString(){
      return this.logauthorization.getViewLogRights();
    }

    /**
     * Returns string used in view log queries.
     */
    public String getViewLogCAIdString(){
      return this.logauthorization.getCARights();
    }
    
    /**
     * Returns CA authorization string used in userdata queries.
     */
    public String getUserDataQueryCAAuthoorizationString(){
      return this.raauthorization.getCAAuthorizationString();   
    }

    /**
     * Returns CA authorization string used in userdata queries.
     */
    public String getUserDataQueryEndEntityProfileAuthorizationString(){
      return this.raauthorization.getEndEntityProfileAuthorizationString();   
    }
    
    
    /**
     * Returns a Collection of Integer containing authorized CA ids.
     */    
    public Collection getAuthorizedCAIds(){
      return caauthorization.getAuthorizedCAIds();  
    } 
    
    /**
     * Returns the system configuration (GlobalConfiguration).
     */    
    public GlobalConfiguration getGlobalConfiguration(){      
      return globalconfiguration;  
    }
    
    /**
     * Returns the end entity profile name proxy
     */      
    public EndEntityProfileNameProxy getEndEntityProfileNameProxy(){
      if(endentityprofilenameproxy == null)
        endentityprofilenameproxy = new EndEntityProfileNameProxy(administrator, raadminsession);  
        
      return endentityprofilenameproxy;
    }
    
    /**
     * Returns the end entity profile name proxy
     */      
    public CertificateProfileNameProxy getCertificateProfileNameProxy(){
      if(certificateprofilenameproxy == null)
        certificateprofilenameproxy = new CertificateProfileNameProxy(administrator, certificatestoresession);  
        
      return certificateprofilenameproxy;
    }
    
    /**
     * Method that calculates them available cas to an end entity. Used in add/edit end entity pages.
     * It calculates a set of available CAs as an intersection of:
     * - The administrators authorized CAs
     * - The end entity profiles available CAs
     * - The certificate profiles available CAs.
     *
     * @param The id of end entity profile to retrieve set form.
     * @returns a HashMap of CertificateProfileId to Collection. It returns a set of avialable CAs per certificate profile.
     */
    
    public HashMap getEndEntityAvailableCAs(int endentityprofileid){
      if(endentityavailablecas == null){
        // Build new structure.  
        Collection authorizedcas = getAuthorizedCAIds();  
          
        HashMap certproftemp = new HashMap();
          
        endentityavailablecas = new HashMap();
        Iterator endentityprofileiter = raadminsession.getAuthorizedEndEntityProfileIds(administrator).iterator();
        while(endentityprofileiter.hasNext()){
           Integer nextendentityprofileid = (Integer) endentityprofileiter.next();
           EndEntityProfile endentityprofile = raadminsession.getEndEntityProfile(administrator,nextendentityprofileid.intValue());
           String[] values   = endentityprofile.getValue(EndEntityProfile.AVAILCAS,0).split(EndEntityProfile.SPLITCHAR); 
           ArrayList endentityprofileavailcas = new ArrayList();
           for(int i=0;i < values.length;i++){
             endentityprofileavailcas.add(new Integer(values[i]));  
           }
           
           boolean endentityprofileallcas = false;
           if(endentityprofileavailcas.contains(new Integer(SecConst.ALLCAS))){
             endentityprofileallcas = true;   
           }
           
           values = endentityprofile.getValue(EndEntityProfile.AVAILCERTPROFILES,0).split(EndEntityProfile.SPLITCHAR); 
           HashMap certificateprofilemap = new HashMap();
           for(int i=0;i < values.length;i++){             
             Integer nextcertprofileid = new Integer(values[i]);
             CertificateProfile certprofile = (CertificateProfile) certproftemp.get(nextcertprofileid);
             if(certprofile == null){
               certprofile = certificatestoresession.getCertificateProfile(administrator,nextcertprofileid.intValue());   
               certproftemp.put(nextcertprofileid,certprofile);
             }
             
             Collection certprofilesavailablecas = certprofile.getAvailableCAs();
             if(certprofilesavailablecas.contains(new Integer(CertificateProfile.ANYCA))){
               ArrayList authorizedcastemp = new ArrayList(authorizedcas);
               if(!endentityprofileallcas)
                 authorizedcastemp.retainAll(endentityprofileavailcas);
               certificateprofilemap.put(nextcertprofileid,authorizedcastemp);
             }else{
               ArrayList authorizedcastemp = new ArrayList(authorizedcas);               
               if(!endentityprofileallcas)
                 authorizedcastemp.retainAll(endentityprofileavailcas);
               authorizedcastemp.retainAll(certprofilesavailablecas);
               certificateprofilemap.put(nextcertprofileid,authorizedcastemp);                 
             }  
           }
           endentityavailablecas.put(nextendentityprofileid, certificateprofilemap);
        } 
      }    
        
      return (HashMap) endentityavailablecas.get(new Integer(endentityprofileid));      
    }

    
    
    /**
     * Method that should be called every time CA configuration is edited.
     */
    public void cAsEdited(){
      caidtonamemap = null;   
      endentityavailablecas = null;
      logauthorization.clear();
      raauthorization.clear();
      caauthorization.clear();
    }
    

    /**
     * Method that should be called every time a end entity profile has been edited
     */
    public void endEntityProfilesEdited(){
      endentityprofileidtonamemap = null;   
      endentityprofilenameproxy = null;
      endentityavailablecas = null;
      raauthorization.clear();
    }    
    
    /**
     * Method that should be called every time a certificate profile has been edited
     */
    public void certificateProfilesEdited(){
      certificateprofileidtonamemap = null;
      certificateprofilenameproxy = null;
      endentityavailablecas = null;
      raauthorization.clear();
      caauthorization.clear();
    }    
    
    /**
     * Method that should be called every time a administrative privilegdes has been edited
     */
    public void administrativePriviledgesEdited(){
      endentityavailablecas = null;  
      logauthorization.clear();   
      raauthorization.clear();
      caauthorization.clear();
    }    
    
    /**
     * Method that should be called every time the system configuration has been edited
     */    
    public void systemConfigurationEdited(GlobalConfiguration globalconfiguration){
      this.globalconfiguration = globalconfiguration;  
    }
    
    
    // Private fields
    private Admin administrator;
    // Session Bean interfaces
    private ICAAdminSessionLocal caadminsession;
    private IRaAdminSessionLocal raadminsession;
    private IAuthorizationSessionLocal authorizationsession;
    private ISignSessionLocal signsession;
    private ICertificateStoreSessionLocal certificatestoresession;
    
    // Memory variables.
    LogAuthorization logauthorization = null;
    RAAuthorization raauthorization = null;
    CAAuthorization caauthorization = null;
    
    HashMap endentityprofileidtonamemap = null;
    HashMap caidtonamemap = null;
    HashMap certificateprofileidtonamemap = null;    
    HashMap endentityavailablecas = null;
    GlobalConfiguration globalconfiguration = null;
    EndEntityProfileNameProxy endentityprofilenameproxy = null;
    CertificateProfileNameProxy certificateprofilenameproxy = null;
}
