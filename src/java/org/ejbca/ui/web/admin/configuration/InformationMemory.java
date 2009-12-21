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
 
/*
 * InformationMemory.java
 *
 * Created on den 14 juli 2003, 14:05
 */

package org.ejbca.ui.web.admin.configuration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.TreeMap;

import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.ui.web.admin.cainterface.CAAuthorization;
import org.ejbca.ui.web.admin.cainterface.CertificateProfileNameProxy;
import org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization;
import org.ejbca.ui.web.admin.loginterface.LogAuthorization;
import org.ejbca.ui.web.admin.rainterface.EndEntityProfileNameProxy;


/**
 * A class used to improve performance by proxying authorization information about the administrator.
 * It should be used in all jsp interface bean classes. 
 * @author  TomSelleck
 * @version $Id$
 */
public class InformationMemory implements java.io.Serializable {
    
    /** Creates a new instance of ProfileNameProxy */
    public InformationMemory(Admin administrator,
                             ICAAdminSessionLocal  caadminsession,
                             IRaAdminSessionLocal raadminsession, 
                             IAuthorizationSessionLocal authorizationsession,
                             ICertificateStoreSessionLocal certificatestoresession,
                             IHardTokenSessionLocal hardtokensession,
							 IPublisherSessionLocal publishersession,
							 IUserDataSourceSessionLocal userdatasourcesession,
                             GlobalConfiguration globalconfiguration){
      this.caadminsession = caadminsession;                           
      this.administrator = administrator;
      this.raadminsession = raadminsession;
      this.authorizationsession = authorizationsession;
      this.certificatestoresession = certificatestoresession;
      this.publishersession = publishersession;
      this.userdatasourcesession = userdatasourcesession;
      this.globalconfiguration = globalconfiguration;
      
      this.raauthorization = new RAAuthorization(administrator, raadminsession, authorizationsession, caadminsession);
      this.caauthorization = new CAAuthorization(administrator, caadminsession, certificatestoresession, authorizationsession);
      this.logauthorization = new LogAuthorization(administrator, authorizationsession, caadminsession);
      this.hardtokenauthorization = new HardTokenAuthorization(administrator, hardtokensession, authorizationsession, caadminsession);
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
	 * Returns a Map of hard token profile id (Integer) -> hard token profile name (String).
	 */
	public HashMap getHardTokenProfileIdToNameMap(){      
	  return this.hardtokenauthorization.getHardTokenProfileIdToNameMap();
	}            
    
    /**
     * Returns authorized end entity profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap getAuthorizedEndEntityProfileNames(){
      return this.raauthorization.getAuthorizedEndEntityProfileNames();   
    }
    
	/**
	 * Returns end entity profile names with create rights as a treemap of name (String) -> id (Integer)
	 */    
    public TreeMap getCreateAuthorizedEndEntityProfileNames(){
		if(globalconfiguration.getEnableEndEntityProfileLimitations())
		  return this.raauthorization.getCreateAuthorizedEndEntityProfileNames();
		  
		return this.raauthorization.getAuthorizedEndEntityProfileNames(); 
    }

	/**
	 * Returns end entity profile names with view rights as a treemap of name (String) -> id (Integer)
	 */    
	public TreeMap getViewAuthorizedEndEntityProfileNames(){
		if(globalconfiguration.getEnableEndEntityProfileLimitations())
		  return this.raauthorization.getViewAuthorizedEndEntityProfileNames();
		  
		return this.raauthorization.getAuthorizedEndEntityProfileNames();   
	}

    
    /**
     * Returns authorized end entity certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap getAuthorizedEndEntityCertificateProfileNames(){
      return this.caauthorization.getAuthorizedEndEntityCertificateProfileNames(getGlobalConfiguration().getIssueHardwareTokens());   
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
    public TreeMap getEditCertificateProfileNames(){
      return this.caauthorization.getEditCertificateProfileNames(getGlobalConfiguration().getIssueHardwareTokens());   
    }     
    
    /**
     * Returns a CA names as a treemap of name (String) -> id (Integer).
     * Doesn't include external CAs.
     */
    public TreeMap getCANames(){
      return this.caauthorization.getCANames();   
    }     
 
	/**
	 * Returns a CA names as a treemap of name (String) -> id (Integer).
	 * Also includes external CAs
	 */
	public TreeMap getAllCANames(){
	  return this.caauthorization.getAllCANames();   
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
     *  Returns a collection of module ids the administrator is authorized to view log of.
     */
    public Collection getAuthorizedModules(){
        return this.logauthorization.getAuthorizedModules();       	
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
      return this.raauthorization.getEndEntityProfileAuthorizationString(true);   
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
     *  Method returning the all available publishers id to name.
     * 
     * @return the publisheridtonamemap (HashMap)
     */
    public HashMap getPublisherIdToNameMap(){
    	if(publisheridtonamemap == null)
    	   publisheridtonamemap = publishersession.getPublisherIdToNameMap(administrator);
    	   
    	 return publisheridtonamemap;   	
    }
    
    /**
     * Returns all authorized publishers names as a treemap of name (String) -> id (Integer).
     */
    public TreeMap getAuthorizedPublisherNames(){
    	if(publishernames==null){
    		publishernames = new TreeMap();  
    		Iterator iter = caadminsession.getAuthorizedPublisherIds(administrator).iterator();      
    		HashMap idtonamemap = getPublisherIdToNameMap();
    		while(iter.hasNext()){
    			Integer id = (Integer) iter.next();
    			publishernames.put(idtonamemap.get(id),id);
    		}
    	}
    	return publishernames;
    }
        
    /**
     * Method that calculates the available cas to an end entity. Used in add/edit end entity pages.
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
     *  Returns a administrators set of authorized available accessrules.
     * 
     * @return A HashSet containing the administrators authorized available accessrules.
     */

    public HashSet getAuthorizedAccessRules(){
      if(authorizedaccessrules == null)
	    authorizedaccessrules = new HashSet(authorizationsession.getAuthorizedAvailableAccessRules(administrator, caadminsession.getAvailableCAs(administrator),
	    		globalconfiguration.getEnableEndEntityProfileLimitations(), globalconfiguration.getIssueHardwareTokens(), globalconfiguration.getEnableKeyRecovery(),
	    		raadminsession.getAuthorizedEndEntityProfileIds(administrator), userdatasourcesession.getAuthorizedUserDataSourceIds(administrator, true)));
	    
	   return authorizedaccessrules;
    }

	/**
	 *  @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
	 */	
	public TreeMap getHardTokenProfiles(){	  	    
	   return hardtokenauthorization.getHardTokenProfiles();
	}
	
	/**
	 *  @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
	 */	
	public boolean authorizedToHardTokenProfiles(String name){			  	    
	   return hardtokenauthorization.authorizedToHardTokenProfile(name);
	}
    
	/**
	 *  @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
	 */	
	public TreeMap getHardTokenIssuers(){	  	    
	   return hardtokenauthorization.getHardTokenIssuers();
	}
	
	/**
	 *  @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
	 */	
	public boolean authorizedToHardTokenIssuer(String alias){			  	    
	   return hardtokenauthorization.authorizedToHardTokenIssuer(alias);
	}	


	/**
	 *  @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
	 */	
	public Collection getHardTokenIssuingAdminGroups(){
	  return hardtokenauthorization.getHardTokenIssuingAdminGroups();	
	}

    /**
     * Returns a sorted map with authorized admingroupname -> admingroupid
     */

    public TreeMap getAuthorizedAdminGroups(){
      if(authgroups == null){
        authgroups = new TreeMap();
        Iterator iter = this.authorizationsession.getAuthorizedAdminGroupNames(administrator, caadminsession.getAvailableCAs(administrator)).iterator();
        while(iter.hasNext()){
          AdminGroup admingroup = (AdminGroup) iter.next();	
          authgroups.put(admingroup.getAdminGroupName(),new Integer(admingroup.getAdminGroupId()));
        }              		
      }
      return authgroups;	 
    }


	/**
	 * Returns a map with authorized admingroupid -> admingroupname
	 */
    
    public HashMap getAdminGroupIdToNameMap(){
      if(admingrpidmap == null){
      	TreeMap admingrpnames = getAuthorizedAdminGroups();
		admingrpidmap = new HashMap();
      	Iterator iter = admingrpnames.keySet().iterator();
      	while(iter.hasNext()){
      		Object next = iter.next();
			admingrpidmap.put(admingrpnames.get(next) ,next);	
      	}			
      	
      }
    	
      return admingrpidmap;	
    }

    
    /**
     * Method that should be called every time CA configuration is edited.
     */
    public void cAsEdited(){
      authgroups = null;
      admingrpidmap = null;
      caidtonamemap = null;   
      endentityavailablecas = null;
	  authorizedaccessrules = null;
      logauthorization.clear();
      raauthorization.clear();
      caauthorization.clear();
      hardtokenauthorization.clear();
    }
    

    /**
     * Method that should be called every time a end entity profile has been edited
     */
    public void endEntityProfilesEdited(){
      endentityprofileidtonamemap = null;   
      endentityprofilenameproxy = null;
      endentityavailablecas = null;
	  authorizedaccessrules = null;
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
      hardtokenauthorization.clear();
    }
    
    /**
     * Method that should be called every time a publisher has been edited
     */
    public void publishersEdited(){
    	publisheridtonamemap = null;
    	publishernames = null;    	
    } 
    
    /**
     * Method that should be called every time a administrative privilegdes has been edited
     */
    public void administrativePriviledgesEdited(){
      endentityavailablecas = null;
	  authgroups = null;  
	  admingrpidmap = null;
      logauthorization.clear();   
      raauthorization.clear();
      caauthorization.clear();
	  hardtokenauthorization.clear();
    }    

	/**
	 * Method that should be called every time hard token issuers has been edited
	 */
	public void hardTokenDataEdited(){	 
	  hardtokenauthorization.clear();
	}    

    
    /**
     * Method that should be called every time the system configuration has been edited
     */    
    public void systemConfigurationEdited(GlobalConfiguration globalconfiguration){
      this.globalconfiguration = globalconfiguration;
	  logauthorization.clear();   
	  raauthorization.clear();
	  caauthorization.clear();
	  hardtokenauthorization.clear();
	  authorizedaccessrules = null;
    }
    
    /**
     * Method that should be called every time the system configuration has been edited
     */    
    public void userDataSourceEdited(){      
    	authorizedaccessrules = null;
    }
    
    
    // Private fields
    private Admin administrator;
    // Session Bean interfaces
    private ICAAdminSessionLocal caadminsession;
    private IRaAdminSessionLocal raadminsession;
    private IAuthorizationSessionLocal authorizationsession;
    private IPublisherSessionLocal publishersession;
    private ICertificateStoreSessionLocal certificatestoresession;
    private IUserDataSourceSessionLocal userdatasourcesession = null;
    
    // Memory variables.
    LogAuthorization logauthorization = null;
    RAAuthorization raauthorization = null;
    CAAuthorization caauthorization = null;
    HardTokenAuthorization hardtokenauthorization = null;
    
    HashMap endentityprofileidtonamemap = null;
    HashMap caidtonamemap = null;
    HashMap certificateprofileidtonamemap = null;    
    HashMap endentityavailablecas = null;
    HashMap publisheridtonamemap = null;

    TreeMap authgroups = null;
    TreeMap publishernames = null;
    HashMap admingrpidmap = null;
    
    HashSet authorizedaccessrules = null;
    
    GlobalConfiguration globalconfiguration = null;
    EndEntityProfileNameProxy endentityprofilenameproxy = null;
    CertificateProfileNameProxy certificateprofilenameproxy = null;
}
