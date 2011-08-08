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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.publisher.PublisherSession;
import org.ejbca.core.ejb.config.GlobalConfigurationSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSession;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSession;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.hardtoken.HardTokenIssuerData;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
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
public class InformationMemory implements Serializable {
    
    private static final long serialVersionUID = 1L;
    // Private fields
    private AuthenticationToken administrator;
    // Session Bean interfaces (was *Local originally)
    private CAAdminSession caadminsession;
    private CaSession caSession;
    private AccessControlSessionLocal authorizationsession;
    private EndEntityProfileSession endEntityProfileSession;
    private PublisherSession publishersession;
    private UserDataSourceSession userdatasourcesession = null;
    private CertificateProfileSession certificateProfileSession;
    
    // Memory variables.
    LogAuthorization logauthorization = null;
    RAAuthorization raauthorization = null;
    CAAuthorization caauthorization = null;
    HardTokenAuthorization hardtokenauthorization = null;
    
    Map<Integer, String>  caidtonamemap = null;
    Map<Integer, HashMap<Integer, List>> endentityavailablecas = null;
    Map<Integer,String> publisheridtonamemap = null;

    TreeMap<String, Integer> authgroups = null;
    TreeMap<String, Integer> publishernames = null;
    Map<Integer, String> admingrpidmap = null;
    
    HashSet<String> authorizedaccessrules = null;
    
    GlobalConfiguration globalconfiguration = null;
    EndEntityProfileNameProxy endentityprofilenameproxy = null;
    CertificateProfileNameProxy certificateprofilenameproxy = null;

    /** Creates a new instance of ProfileNameProxy */
    public InformationMemory(AuthenticationToken administrator,
                             CAAdminSession caadminsession, CaSession caSession,
                             RaAdminSession raadminsession,
                             AccessControlSessionLocal authorizationsession,
                             EndEntityProfileSession endEntityProfileSession,
                             HardTokenSession hardtokensession,
                             PublisherSession publishersession,
                             UserDataSourceSession userdatasourcesession, 
                             CertificateProfileSession certificateProfileSession,
                             GlobalConfigurationSession globalConfigurationSession,
                             GlobalConfiguration globalconfiguration){
        this.caadminsession = caadminsession;                           
      this.administrator = administrator;
      this.authorizationsession = authorizationsession;
      this.endEntityProfileSession = endEntityProfileSession;
      this.publishersession = publishersession;
      this.userdatasourcesession = userdatasourcesession;
      this.globalconfiguration = globalconfiguration;
      this.certificateProfileSession = certificateProfileSession;
      this.caSession = caSession;
      this.raauthorization = new RAAuthorization(administrator, globalConfigurationSession, authorizationsession, caSession, endEntityProfileSession);
      this.caauthorization = new CAAuthorization(administrator, caadminsession, caSession, authorizationsession, certificateProfileSession);
      this.logauthorization = new LogAuthorization(administrator, authorizationsession, caSession);
      this.hardtokenauthorization = new HardTokenAuthorization(administrator, adminGroupSession, hardtokensession, authorizationsession, caSession);
    }

    public String getCertificateProfileName(int id){
    	return this.certificateProfileSession.getCertificateProfileName(id);
    }
    
    /**
     * Returns a Map of CA id (Integer) -> CA name (String).
     */
    public Map<Integer, String>  getCAIdToNameMap(){
      if(caidtonamemap == null){
        caidtonamemap = caadminsession.getCAIdToNameMap(administrator);
      }
      
      return caidtonamemap;
    }
    
	/**
	 * Returns a Map of hard token profile id (Integer) -> hard token profile name (String).
	 */
	public Map<Integer, String> getHardTokenProfileIdToNameMap(){      
	  return this.hardtokenauthorization.getHardTokenProfileIdToNameMap();
	}            
    
    /**
     * Returns authorized end entity profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedEndEntityProfileNames(){
      return this.raauthorization.getAuthorizedEndEntityProfileNames();   
    }
    
	/**
	 * Returns end entity profile names with create rights as a treemap of name (String) -> id (Integer)
	 */    
    public TreeMap<String, Integer> getCreateAuthorizedEndEntityProfileNames(){
		if(globalconfiguration.getEnableEndEntityProfileLimitations()) {
		  return this.raauthorization.getCreateAuthorizedEndEntityProfileNames();
		}
		return this.raauthorization.getAuthorizedEndEntityProfileNames(); 
    }

	/**
	 * Returns end entity profile names with view rights as a treemap of name (String) -> id (Integer)
	 */    
	public TreeMap<String, Integer> getViewAuthorizedEndEntityProfileNames(){
		if(globalconfiguration.getEnableEndEntityProfileLimitations()) {
		  return this.raauthorization.getViewAuthorizedEndEntityProfileNames();
		}
		return this.raauthorization.getAuthorizedEndEntityProfileNames();   
	}

    
    /**
     * Returns authorized end entity certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedEndEntityCertificateProfileNames(){
      return this.caauthorization.getAuthorizedEndEntityCertificateProfileNames(getGlobalConfiguration().getIssueHardwareTokens());   
    }    

    /**
     * Returns authorized sub CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedSubCACertificateProfileNames(){
      return this.caauthorization.getAuthorizedSubCACertificateProfileNames();   
    } 
    
    /**
     * Returns authorized root CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getAuthorizedRootCACertificateProfileNames(){
      return this.caauthorization.getAuthorizedRootCACertificateProfileNames();   
    } 
    
    /**
     * Returns all authorized certificate profile names as a treemap of name (String) -> id (Integer)
     */
    public TreeMap<String, Integer> getEditCertificateProfileNames(){
      return this.caauthorization.getEditCertificateProfileNames(getGlobalConfiguration().getIssueHardwareTokens());   
    }     
    
    /**
     * Returns a CA names as a treemap of name (String) -> id (Integer).
     * Doesn't include external CAs.
     */
    public TreeMap<String, Integer> getCANames(){
      return this.caauthorization.getCANames();   
    }     
 
	/**
	 * Returns a CA names as a treemap of name (String) -> id (Integer).
	 * Also includes external CAs
	 */
	public TreeMap<String, Integer> getAllCANames(){
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
    public Collection<Integer> getAuthorizedModules(){
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
    public Collection<Integer> getAuthorizedCAIds(){
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
      if(endentityprofilenameproxy == null) {
        endentityprofilenameproxy = new EndEntityProfileNameProxy(administrator, endEntityProfileSession);  
      }
      return endentityprofilenameproxy;
    }
    
    /**
     * Returns the end entity profile name proxy
     */      
    public CertificateProfileNameProxy getCertificateProfileNameProxy(){
      if(certificateprofilenameproxy == null) {
        certificateprofilenameproxy = new CertificateProfileNameProxy(administrator, certificateProfileSession);  
      }
      return certificateprofilenameproxy;
    }
    
    /**
     *  Method returning the all available publishers id to name.
     * 
     * @return the publisheridtonamemap (HashMap)
     */
    public Map<Integer,String> getPublisherIdToNameMap(){
    	if(publisheridtonamemap == null) {
    	   publisheridtonamemap = publishersession.getPublisherIdToNameMap(administrator);
    	}
    	 return publisheridtonamemap;   	
    }
    
    /**
     * Returns all authorized publishers names as a treemap of name (String) -> id (Integer).
     */
    public TreeMap<String, Integer> getAuthorizedPublisherNames(){
    	if(publishernames==null){
    		publishernames = new TreeMap<String, Integer>();  
    		Iterator<Integer> iter = caadminsession.getAuthorizedPublisherIds(administrator).iterator();      
    		Map<Integer,String> idtonamemap = getPublisherIdToNameMap();
    		while(iter.hasNext()){
    			Integer id = iter.next();
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
    
    public Map<Integer, List> getEndEntityAvailableCAs(int endentityprofileid){
      if(endentityavailablecas == null){
        // Build new structure.  
        Collection<Integer> authorizedcas = getAuthorizedCAIds();  
          
        HashMap<Integer, CertificateProfile> certproftemp = new HashMap<Integer, CertificateProfile>();
          
        endentityavailablecas = new HashMap<Integer, HashMap<Integer, List>>();
    
        for(Integer nextendentityprofileid : endEntityProfileSession.getAuthorizedEndEntityProfileIds(administrator)){
           EndEntityProfile endentityprofile = endEntityProfileSession.getEndEntityProfile(administrator,nextendentityprofileid.intValue());
           String[] values   = endentityprofile.getValue(EndEntityProfile.AVAILCAS,0).split(EndEntityProfile.SPLITCHAR); 
           ArrayList<Integer> endentityprofileavailcas = new ArrayList<Integer>();
           for(int i=0;i < values.length;i++){
             endentityprofileavailcas.add(Integer.valueOf(values[i]));  
           }
           
           boolean endentityprofileallcas = false;
           if(endentityprofileavailcas.contains(Integer.valueOf(SecConst.ALLCAS))){
             endentityprofileallcas = true;   
           }
           
           values = endentityprofile.getValue(EndEntityProfile.AVAILCERTPROFILES,0).split(EndEntityProfile.SPLITCHAR); 
           HashMap<Integer, List> certificateprofilemap = new HashMap<Integer, List>();
           for(int i=0;i < values.length;i++){             
             Integer nextcertprofileid = Integer.valueOf(values[i]);
             CertificateProfile certprofile = (CertificateProfile) certproftemp.get(nextcertprofileid);
             if(certprofile == null){
               certprofile = certificateProfileSession.getCertificateProfile(nextcertprofileid.intValue());   
               certproftemp.put(nextcertprofileid,certprofile);
             }
             
             Collection<Integer> certprofilesavailablecas = certprofile.getAvailableCAs();
             if(certprofilesavailablecas.contains(Integer.valueOf(CertificateProfile.ANYCA))){
               ArrayList<Integer> authorizedcastemp = new ArrayList<Integer>(authorizedcas);
               if(!endentityprofileallcas) {
                 authorizedcastemp.retainAll(endentityprofileavailcas);
               }
               certificateprofilemap.put(nextcertprofileid,authorizedcastemp);
             }else{
               ArrayList<Integer> authorizedcastemp = new ArrayList<Integer>(authorizedcas);               
               if(!endentityprofileallcas) {
                 authorizedcastemp.retainAll(endentityprofileavailcas);
               }
               authorizedcastemp.retainAll(certprofilesavailablecas);
               certificateprofilemap.put(nextcertprofileid,authorizedcastemp);                 
             }  
           }
           endentityavailablecas.put(nextendentityprofileid, certificateprofilemap);
        } 
      }    
        
      return endentityavailablecas.get(Integer.valueOf(endentityprofileid));      
    }

    /**
     *  Returns a administrators set of authorized available accessrules.
     * 
     * @return A HashSet containing the administrators authorized available accessrules.
     */

    public HashSet<String> getAuthorizedAccessRules(){
      if(authorizedaccessrules == null) {
	    authorizedaccessrules = new HashSet<String>(authorizationsession.getAuthorizedAvailableAccessRules(administrator, caSession.getAvailableCAs(administrator),
	    		globalconfiguration.getEnableEndEntityProfileLimitations(), globalconfiguration.getIssueHardwareTokens(), globalconfiguration.getEnableKeyRecovery(),
	    		endEntityProfileSession.getAuthorizedEndEntityProfileIds(administrator), userdatasourcesession.getAuthorizedUserDataSourceIds(administrator, true)));
      }
	   return authorizedaccessrules;
    }

	/**
	 *  @see org.ejbca.ui.web.admin.hardtokeninterface.HardTokenAuthorization.java
	 */	
	public TreeMap<String, Integer> getHardTokenProfiles(){	  	    
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
	public TreeMap<String, HardTokenIssuerData> getHardTokenIssuers(){	  	    
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
	public Collection<AdminGroup> getHardTokenIssuingAdminGroups(){
	  return hardtokenauthorization.getHardTokenIssuingAdminGroups();	
	}

    /**
     * Returns a sorted map with authorized admingroupname -> admingroupid
     */

    public TreeMap<String, Integer> getAuthorizedAdminGroups(){
      if(authgroups == null){
        authgroups = new TreeMap<String, Integer>();
        Iterator<AdminGroup> iter = this.adminGroupSession.getAuthorizedAdminGroupNames(administrator, caSession.getAvailableCAs(administrator)).iterator();
        while(iter.hasNext()){
          AdminGroup admingroup = iter.next();	
          authgroups.put(admingroup.getAdminGroupName(),Integer.valueOf(admingroup.getAdminGroupId()));
        }              		
      }
      return authgroups;	 
    }


	/**
	 * Returns a map with authorized admingroupid -> admingroupname
	 */
    
    public Map<Integer, String> getAdminGroupIdToNameMap(){
      if(admingrpidmap == null){
      	TreeMap<String, Integer> admingrpnames = getAuthorizedAdminGroups();
		admingrpidmap = new HashMap<Integer, String>();
      	Iterator<String> iter = admingrpnames.keySet().iterator();
      	while(iter.hasNext()){
      		String next = iter.next();
			admingrpidmap.put(admingrpnames.get(next), next);	
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
      endentityprofilenameproxy = null;
      endentityavailablecas = null;
	  authorizedaccessrules = null;
      raauthorization.clear();
    }    
    
    /**
     * Method that should be called every time a certificate profile has been edited
     */
    public void certificateProfilesEdited(){
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
}
