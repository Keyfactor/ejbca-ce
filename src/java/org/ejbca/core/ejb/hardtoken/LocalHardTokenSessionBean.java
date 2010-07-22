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

package org.ejbca.core.ejb.hardtoken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;
import java.util.TreeMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceResponse;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerData;
import org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;
import org.ejbca.core.model.hardtoken.UnavailableTokenException;
import org.ejbca.core.model.hardtoken.profiles.EIDProfile;
import org.ejbca.core.model.hardtoken.profiles.EnhancedEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.core.model.hardtoken.profiles.SwedishEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.TurkishEIDProfile;
import org.ejbca.core.model.hardtoken.types.EIDHardToken;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.hardtoken.types.TurkishEIDHardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.UserAdminConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;



/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @ejb.bean
 *   description="Session bean handling hard token data, both about hard tokens and hard token issuers."
 *   display-name="HardTokenSessionSB"
 *   name="HardTokenSession"
 *   jndi-name="HardTokenSession"
 *   local-jndi-name="HardTokenSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Supports"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry
 *   description="The JDBC datasource to be used"
 *  name="DataSource"
 *  type="java.lang.String"
 *  value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.hardtoken.IHardTokenSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal"
 *   remote-class="org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote"
 *
 * @ejb.ejb-external-ref
 *   description="The hard token profile data entity bean"
 *   view-type="local"
 *   ref-name="ejb/HardTokenProfileDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.hardtoken.HardTokenProfileDataLocalHome"
 *   business="org.ejbca.core.ejb.hardtoken.HardTokenProfileDataLocal"
 *   link="HardTokenProfileData"
 *
 * @ejb.ejb-external-ref
 *   description="The hard token issuers data entity bean"
 *   view-type="local"
 *   ref-name="ejb/HardTokenIssuerDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.hardtoken.HardTokenIssuerDataLocalHome"
 *   business="org.ejbca.core.ejb.hardtoken.HardTokenIssuerDataLocal"
 *   link="HardTokenIssuerData"
 *
 * @ejb.ejb-external-ref
 *   description="The hard token data entity bean"
 *   view-type="local"
 *   ref-name="ejb/HardTokenDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.hardtoken.HardTokenDataLocalHome"
 *   business="org.ejbca.core.ejb.hardtoken.HardTokenDataLocal"
 *   link="HardTokenData"
 *
 * @ejb.ejb-external-ref
 *   description="The hard token property data entity bean"
 *   view-type="local"
 *   ref-name="ejb/HardTokenPropertyDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.hardtoken.HardTokenPropertyLocalHome"
 *   business="org.ejbca.core.ejb.hardtoken.HardTokenPropertyLocal"
 *   link="HardTokenPropertyData"
 *
 * @ejb.ejb-external-ref
 *   description="The hard token to certificate map data entity bean"
 *   view-type="local"
 *   ref-name="ejb/HardTokenCertificateMapLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.hardtoken.HardTokenCertificateMapLocalHome"
 *   business="org.ejbca.core.ejb.hardtoken.HardTokenCertificateMapLocal"
 *   link="HardTokenCertificateMap"
 *
 * @ejb.ejb-external-ref
 *   description="The Authorization session bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Certificate Store session bean"
 *   view-type="local"
 *   ref-name="ejb/CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *   
 * @ejb.ejb-external-ref description="The Sign Session Bean"
 *   view-type="local"
 *   ref-name="ejb/RSASignSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *   link="RSASignSession"
 *   
 * @ejb.ejb-external-ref
 *   description="The RA Session Bean"
 *   view-type="local"
 *   ref-name="ejb/RaAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal"
 *   link="RaAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @jonas.bean
 *   ejb-name="HardTokenSession"
 *
 */
public class LocalHardTokenSessionBean extends BaseSessionBean  {

    public static final int NO_ISSUER = 0;

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** The local home interface of hard token issuer entity bean. */
    private HardTokenIssuerDataLocalHome hardtokenissuerhome = null;

    /** The local home interface of hard token entity bean. */
    private HardTokenDataLocalHome hardtokendatahome = null;

	/** The local home interface of hard token entity bean. */
	private HardTokenProfileDataLocalHome hardtokenprofilehome = null;

    /** The local home interface of hard token certificate map entity bean. */
    private HardTokenCertificateMapLocalHome hardtokencertificatemaphome = null;

    /** The local home interface of hard token property entity bean. */
    private HardTokenPropertyLocalHome hardtokenpropertyhome = null;

    /** The local interface of authorization session bean */
    private IAuthorizationSessionLocal authorizationsession = null;

    /** The local interface of certificate store session bean */
    private ICertificateStoreSessionLocal certificatestoresession = null;
    
    private ICAAdminSessionLocal caAdminSession;
    
    /**
     * The local interface of  raadmin session bean
     */
    private IRaAdminSessionLocal raadminsession = null;
    
    /** The home interface of SignSession session bean */
    private ISignSessionLocal signsession;

    /** The remote interface of  log session bean */
    private ILogSessionLocal logsession = null;




     /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */


    public void ejbCreate() throws CreateException {
      try{
        hardtokenissuerhome = (HardTokenIssuerDataLocalHome) getLocator().getLocalHome(HardTokenIssuerDataLocalHome.COMP_NAME);
        hardtokendatahome = (HardTokenDataLocalHome) getLocator().getLocalHome(HardTokenDataLocalHome.COMP_NAME);
        hardtokencertificatemaphome = (HardTokenCertificateMapLocalHome) getLocator().getLocalHome(HardTokenCertificateMapLocalHome.COMP_NAME);
		hardtokenprofilehome = (HardTokenProfileDataLocalHome) getLocator().getLocalHome(HardTokenProfileDataLocalHome.COMP_NAME);
		hardtokenpropertyhome = (HardTokenPropertyLocalHome) getLocator().getLocalHome(HardTokenPropertyLocalHome.COMP_NAME);
      }catch(Exception e){
         throw new EJBException(e);
      }
    }


    /** Gets connection to log session bean
     * @return Connection
     */
    private ILogSessionLocal getLogSession() {
        if(logsession == null){
          try{
            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
            logsession = logsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return logsession;
    } //getLogSession

    /**
     * Gets connection to caadmin session bean
     *
     * @return ICAAdminSessionLocal
     */
    private ICAAdminSessionLocal getCAAdminSession() {
        if (caAdminSession == null) {
            try {
                ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
                caAdminSession = caadminsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return caAdminSession;
    } //getCAAdminSession

    /** Gets connection to certificate store session bean
     * @return Connection
     */
    private ICertificateStoreSessionLocal getCertificateStoreSession() {
        if(certificatestoresession == null){
          try{
            ICertificateStoreSessionLocalHome certificatestoresessionhome = (ICertificateStoreSessionLocalHome) getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
            certificatestoresession = certificatestoresessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return certificatestoresession;
    } //getCertificateStoreSession

    /** Gets connection to sign session bean
     * @return Connection
     */
    private ISignSessionLocal getSignSession() {
        if(signsession == null){
          try{
        	  ISignSessionLocalHome signsessionhome = (ISignSessionLocalHome) getLocator().getLocalHome(ISignSessionLocalHome.COMP_NAME);
              signsession = signsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return signsession;
    } //getSignSession
    
    /**
     * Gets connection to ra admin session bean
     *
     * @return Connection
     */
    private IRaAdminSessionLocal getRaAdminSession() {
        if (raadminsession == null) {
            try {
                IRaAdminSessionLocalHome home = (IRaAdminSessionLocalHome) ServiceLocator.getInstance()
                        .getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
                raadminsession = home.create();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }
        return raadminsession;
    } //getRaAdminSession

    
    /** Gets connection to authorization session bean
     * @return IAuthorizationSessionLocal
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if(authorizationsession == null){
          try{
            IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) getLocator().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
            authorizationsession = authorizationsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return authorizationsession;
    } //getAuthorizationSession





	/**
	 * Adds a hard token profile to the database.
	 *
	 * @throws HardTokenProfileExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
	 */
	public void addHardTokenProfile(Admin admin, String name, HardTokenProfile profile) throws HardTokenProfileExistsException{
		if (log.isTraceEnabled()) {
			log.trace(">addHardTokenProfile(name: " + name + ")");
		}
		addHardTokenProfile(admin,findFreeHardTokenProfileId().intValue(),name,profile);
		log.trace("<addHardTokenProfile()");
	} // addHardTokenProfile


	/**
	 * Adds a hard token profile to the database.
	 * Used for importing and exporting profiles from xml-files.
	 *
	 * @throws HardTokenProfileExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
	 */
	public void addHardTokenProfile(Admin admin, int profileid, String name, HardTokenProfile profile) throws HardTokenProfileExistsException{
		if (log.isTraceEnabled()) {
		    log.trace(">addHardTokenProfile(name: " + name + ", id: " + profileid +")");
		}
	    boolean success=false;
	    try{
	        hardtokenprofilehome.findByName(name);
	    }catch(FinderException e){
	        try{
	            hardtokenprofilehome.findByPrimaryKey(new Integer(profileid));
	        }catch(FinderException f){
	            try{
	                hardtokenprofilehome.create(new Integer(profileid), name, profile);
	                success = true;
	            }catch(CreateException g){
	                error("Unexpected error creating new hard token profile: ", g);      
	            }
	        }
	    }
	    
	    if(success) {
            String msg = intres.getLocalizedMessage("hardtoken.addedprofile", name);            	
	        getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA, msg);
	    } else {
            String msg = intres.getLocalizedMessage("hardtoken.erroraddprofile", name);            	
	        getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA, msg);
	    }
	    
	    if(!success) {
	        throw new HardTokenProfileExistsException();
	    }
	    log.trace("<addHardTokenProfile()");
	} // addHardTokenProfile

	/**
	 * Updates hard token profile data
	 *
	 * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
	 */
	public void changeHardTokenProfile(Admin admin, String name, HardTokenProfile profile){
		if (log.isTraceEnabled()) {
			log.trace(">changeHardTokenProfile(name: " + name + ")");
		}
	   boolean success = false;
	   try{
		 HardTokenProfileDataLocal htp = hardtokenprofilehome.findByName(name);
		 htp.setHardTokenProfile(profile);
		 success = true;
	   }catch(FinderException e){}

	   if(success) {
           String msg = intres.getLocalizedMessage("hardtoken.editedprofile", name);            	
           getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA, msg);
	   } else {
           String msg = intres.getLocalizedMessage("hardtoken.erroreditprofile", name);            	
           getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA, msg);
	   }

	   log.trace("<changeHardTokenProfile()");
	} // changeHardTokenProfile

	 /**
	 * Adds a hard token profile with the same content as the original profile,
	 *
	 * @throws HardTokenProfileExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method view-type="both"
      * @ejb.transaction type="Required"
	 */
	public void cloneHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException{
		if (log.isTraceEnabled()) {
			log.trace(">cloneHardTokenProfile(name: " + oldname + ")");
		}
	   HardTokenProfile profiledata = null;
	   try{
		 HardTokenProfileDataLocal htp = hardtokenprofilehome.findByName(oldname);
		 profiledata = (HardTokenProfile) getHardTokenProfile(htp).clone();

         try{
        	 addHardTokenProfile(admin, newname, profiledata);
        	 String msg = intres.getLocalizedMessage("hardtoken.clonedprofile", newname, oldname);            	
        	 getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA, msg);
         }catch(HardTokenProfileExistsException f){
             String msg = intres.getLocalizedMessage("hardtoken.errorcloneprofile", newname, oldname);            	
             getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA, msg);
             throw f;
         }

	   }catch(Exception e){
		  throw new EJBException(e);
	   }

	   log.trace("<cloneHardTokenProfile()");
	} // cloneHardTokenProfile

	 /**
	 * Removes a hard token profile from the database.
	 *
	 * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method view-type="both"
      * @ejb.transaction type="Required"
	 */
	public void removeHardTokenProfile(Admin admin, String name){
		if (log.isTraceEnabled()) {
			log.trace(">removeHardTokenProfile(name: " + name + ")");
		}
	  try{
		HardTokenProfileDataLocal htp = hardtokenprofilehome.findByName(name);
		htp.remove();
        String msg = intres.getLocalizedMessage("hardtoken.removedprofile", name);            	
		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA,msg);
	  }catch(Exception e){
          String msg = intres.getLocalizedMessage("hardtoken.errorremoveprofile", name);            	
          getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA,msg,e);
	  }
	  log.trace("<removeHardTokenProfile()");
	} // removeHardTokenProfile

	 /**
	 * Renames a hard token profile
	 *
	 * @throws HardTokenProfileExistsException if hard token already exists.
	 * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method view-type="both"
      * @ejb.transaction type="Required"
	 */
	public void renameHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException{
		if (log.isTraceEnabled()) {
			log.trace(">renameHardTokenProfile(from " + oldname + " to " + newname + ")");
		}
	   boolean success = false;
	   try{
		  hardtokenprofilehome.findByName(newname);
	   }catch(FinderException e){
		  try{
			 HardTokenProfileDataLocal htp = hardtokenprofilehome.findByName(oldname);
			 htp.setName(newname);
			 success = true;
		  }catch(FinderException g){}
	   }

	   if(success) {
		   String msg = intres.getLocalizedMessage("hardtoken.renamedprofile", oldname, newname);            	
		   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA,msg);
	   } else {
		   String msg = intres.getLocalizedMessage("hardtoken.errorrenameprofile", oldname, newname);            	
		   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA, msg);
	   }

       if(!success) {
	     throw new HardTokenProfileExistsException();
       }
	   log.trace("<renameHardTokenProfile()");
	} // renameHardTokenProfile

	/**
	 * Retrives a Collection of id:s (Integer) to authorized profiles.
	 * 
	 * Authorized hard token profiles are profiles containing only authorized certificate profiles and caids.
	 *
	 * @return Collection of id:s (Integer)
     * @ejb.interface-method view-type="both"
	 */
	public Collection getAuthorizedHardTokenProfileIds(Admin admin){
	  ArrayList returnval = new ArrayList();
	  Collection result = null;

	  HashSet authorizedcertprofiles = new HashSet(getCertificateStoreSession().getAuthorizedCertificateProfileIds(admin, SecConst.CERTTYPE_HARDTOKEN, getCAAdminSession().getAvailableCAs(admin)));
      HashSet authorizedcaids = new HashSet(getCAAdminSession().getAvailableCAs(admin));
	  
	  try{
		result = this.hardtokenprofilehome.findAll();
		Iterator i = result.iterator();
		while(i.hasNext()){
		  HardTokenProfileDataLocal next = (HardTokenProfileDataLocal) i.next();
		  HardTokenProfile profile = getHardTokenProfile(next);

		  if(profile instanceof EIDProfile){
		  	if(authorizedcertprofiles.containsAll(((EIDProfile) profile).getAllCertificateProfileIds()) &&
		  	   authorizedcaids.containsAll(((EIDProfile) profile).getAllCAIds())){
		  	  returnval.add(next.getId());
		  	}
		  }else{
		  	//Implement for other profile types
		  }
		}
	  }catch(FinderException e){}
	  return returnval;
	} // getAuthorizedHardTokenProfileIds

	/**
	 * Method creating a hashmap mapping profile id (Integer) to profile name (String).
     * @ejb.interface-method view-type="both"
	 */
	public HashMap getHardTokenProfileIdToNameMap(Admin admin){
	  HashMap returnval = new HashMap();
	  Collection result = null;

	  try{
		result = hardtokenprofilehome.findAll();
		Iterator i = result.iterator();
		while(i.hasNext()){
		  HardTokenProfileDataLocal next = (HardTokenProfileDataLocal) i.next();
		  returnval.put(next.getId(),next.getName());
		}
	  }catch(FinderException e){}
	  return returnval;
	} // getHardTokenProfileIdToNameMap


	/**
	 * Retrives a named hard token profile.
     * @ejb.interface-method view-type="both"
	 */
	public HardTokenProfile getHardTokenProfile(Admin admin, String name){
	  HardTokenProfile returnval=null;

	   try{
		 returnval = getHardTokenProfile(hardtokenprofilehome.findByName(name));
	   } catch(FinderException e){
		   // return null if we cant find it
	   }
	   return returnval;
	} //  getCertificateProfile

	 /**
      * Finds a hard token profile by id.
      * @ejb.interface-method view-type="both"
	  */
	public HardTokenProfile getHardTokenProfile(Admin admin, int id){
	   HardTokenProfile returnval=null;

  	   try{
		   returnval = getHardTokenProfile(hardtokenprofilehome.findByPrimaryKey(new Integer(id)));
	   } catch(FinderException e){
			 // return null if we cant find it
	   }
	   return returnval;
	} // getHardTokenProfile

	/**
	 * Help method used by hard token profile proxys to indicate if it is time to
	 * update it's profile data.
     * @ejb.interface-method view-type="both"
	 */
	public int getHardTokenProfileUpdateCount(Admin admin, int hardtokenprofileid){
	  int returnval = 0;

	  try{
	  	returnval = (hardtokenprofilehome.findByPrimaryKey(new Integer(hardtokenprofileid))).getUpdateCounter();
	  }catch(FinderException e){}

	  return returnval;
	}


	 /**
	 * Returns a hard token profile id, given it's hard token profile name
	 *
	 *
	 * @return the id or 0 if hardtokenprofile cannot be found.
      * @ejb.interface-method view-type="both"
	 */
	public int getHardTokenProfileId(Admin admin, String name){
	  int returnval = 0;

	  try{
		Integer id = (hardtokenprofilehome.findByName(name)).getId();
		returnval = id.intValue();
	  }catch(FinderException e){}

	  return returnval;
	} // getHardTokenProfileId

     /**
      * Returns a hard token profile name given its id.
 	  *
	  * @return the name or null if id noesnt exists
	  * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method view-type="both"
	  */
	public String getHardTokenProfileName(Admin admin, int id){
		if (log.isTraceEnabled()) {
			log.trace(">getHardTokenProfileName(id: " + id + ")");
		}
	  String returnval = null;
	  HardTokenProfileDataLocal htp = null;
	  try{
		htp = hardtokenprofilehome.findByPrimaryKey(new Integer(id));
		if(htp != null){
		  returnval = htp.getName();
		}
	  }catch(FinderException e){}

	  log.trace("<getHardTokenProfileName()");
	  return returnval;
	} // getHardTokenProfileName


    /**
     * Adds a hard token issuer to the database.
     *
     * @return false if hard token issuer already exists.
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */

    public boolean addHardTokenIssuer(Admin admin, String alias, int admingroupid, HardTokenIssuer issuerdata){
		if (log.isTraceEnabled()) {
			log.trace(">addHardTokenIssuer(alias: " + alias + ")");
		}
       boolean returnval=false;
       try{
          hardtokenissuerhome.findByAlias(alias);
       }catch(FinderException e){
         try{
           hardtokenissuerhome.create(findFreeHardTokenIssuerId(), alias, admingroupid, issuerdata);
           returnval = true;
         }catch(CreateException g){}
       }

       if(returnval) {
    	   String msg = intres.getLocalizedMessage("hardtoken.addedissuer", alias);            	
    	   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENISSUERDATA,msg);
       } else {
    	   String msg = intres.getLocalizedMessage("hardtoken.erroraddissuer", alias);            	
    	   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA,msg);
       }

       log.trace("<addHardTokenIssuer()");
       return returnval;
    } // addHardTokenIssuer

    /**
     * Updates hard token issuer data
     *
     * @return false if  alias doesn't exists
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */

    public boolean changeHardTokenIssuer(Admin admin, String alias, HardTokenIssuer issuerdata){
		if (log.isTraceEnabled()) {
			log.trace(">changeHardTokenIssuer(alias: " + alias + ")");
		}
       boolean returnvalue = false;
       try{
         HardTokenIssuerDataLocal htih = hardtokenissuerhome.findByAlias(alias);
         htih.setHardTokenIssuer(issuerdata);
         returnvalue = true;
       }catch(FinderException e){}

       if(returnvalue) {
    	   String msg = intres.getLocalizedMessage("hardtoken.editedissuer", alias);            	
    	   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENISSUERDATA,msg);
       } else {
    	   String msg = intres.getLocalizedMessage("hardtoken.erroreditissuer", alias);            	
    	   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA,msg);
       }

       log.trace("<changeHardTokenIssuer()");
       return returnvalue;
    } // changeHardTokenIssuer

     /**
     * Adds a hard token issuer with the same content as the original issuer,
     *
     * @return false if the new alias or certificatesn already exists.
     * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method view-type="both"
      * @ejb.transaction type="Required"
     */
    public boolean cloneHardTokenIssuer(Admin admin, String oldalias, String newalias, int admingroupid){
		if (log.isTraceEnabled()) {
			log.trace(">cloneHardTokenIssuer(alias: " + oldalias + ")");
		}
       HardTokenIssuer issuerdata = null;
       boolean returnval = false;
       try{
         HardTokenIssuerDataLocal htih = hardtokenissuerhome.findByAlias(oldalias);
         issuerdata = (HardTokenIssuer) htih.getHardTokenIssuer().clone();

         returnval = addHardTokenIssuer(admin, newalias, admingroupid, issuerdata);
         if(returnval) {
        	 String msg = intres.getLocalizedMessage("hardtoken.clonedissuer", newalias, oldalias);            	
        	 getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENISSUERDATA,msg);
         } else {
        	 String msg = intres.getLocalizedMessage("hardtoken.errorcloneissuer", newalias, oldalias);            	
        	 getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA,msg);
         }
       }catch(Exception e){
          throw new EJBException(e);
       }

       log.trace("<cloneHardTokenIssuer()");
       return returnval;
    } // cloneHardTokenIssuer

     /**
     * Removes a hard token issuer from the database.
     *
     * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method view-type="both"
      * @ejb.transaction type="Required"
     */
    public void removeHardTokenIssuer(Admin admin, String alias){
		if (log.isTraceEnabled()) {
			log.trace(">removeHardTokenIssuer(alias: " + alias + ")");
		}
      try{
    	  HardTokenIssuerDataLocal htih = hardtokenissuerhome.findByAlias(alias);
    	  htih.remove();
    	  String msg = intres.getLocalizedMessage("hardtoken.removedissuer", alias);            	
    	  getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENISSUERDATA,msg);
      }catch(Exception e){
    	  String msg = intres.getLocalizedMessage("hardtoken.errorremoveissuer", alias);            	
    	  getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA,msg,e);
      }
      log.trace("<removeHardTokenIssuer()");
    } // removeHardTokenIssuer

     /**
     * Renames a hard token issuer
     *
     * @return false if new alias or certificatesn already exists
     * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method view-type="both"
      * @ejb.transaction type="Required"
     */
    public boolean renameHardTokenIssuer(Admin admin, String oldalias, String newalias,
                                         int newadmingroupid){
		if (log.isTraceEnabled()) {
			log.trace(">renameHardTokenIssuer(from " + oldalias + " to " + newalias + ")");
		}
       boolean returnvalue = false;
       try{
          hardtokenissuerhome.findByAlias(newalias);
       }catch(FinderException e){
           try{
             HardTokenIssuerDataLocal htih = hardtokenissuerhome.findByAlias(oldalias);
             htih.setAlias(newalias);
             htih.setAdminGroupId(newadmingroupid);
             returnvalue = true;
           }catch(FinderException g){}
       }

       if(returnvalue) {
    	   String msg = intres.getLocalizedMessage("hardtoken.renameissuer", oldalias, newalias);            	
    	   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENISSUERDATA,msg );
       } else {
    	   String msg = intres.getLocalizedMessage("hardtoken.errorrenameissuer", oldalias, newalias);            	
    	   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA,msg);
       }

       log.trace("<renameHardTokenIssuer()");
       return returnvalue;
    } // renameHardTokenIssuer

    /**
     * Method to check if an administrator is authorized to issue hard tokens for
     * the given alias.
     *
     * @param admin administrator to check
     * @param alias alias of hardtoken issuer.
     * @return true if administrator is authorized to issue hardtoken with given alias.
     * @ejb.interface-method view-type="both"
     */
    public boolean getAuthorizedToHardTokenIssuer(Admin admin, String alias){
		if (log.isTraceEnabled()) {
			log.trace(">getAuthorizedToHardTokenIssuer(" +  alias + ")");
		}
		boolean returnval = false;
		try {
			int admingroupid = hardtokenissuerhome.findByAlias(alias).getAdminGroupId();
			returnval = getAuthorizationSession().isAuthorizedNoLog(admin, "/hardtoken_functionality/issue_hardtokens");
			returnval = returnval && authorizationsession.existsAdministratorInGroup(admin, admingroupid);
		} catch (FinderException fe) {
		} catch (AuthorizationDeniedException ade) {
		}
		log.trace("<getAuthorizedToHardTokenIssuer(" +  returnval + ")");
      return returnval;
    }

      /**
       * Returns the available hard token issuers authorized to the administrator.
       *
       * @return A collection of available HardTokenIssuerData.
       * @throws EJBException if a communication or other error occurs.
       * @ejb.interface-method view-type="both"
       */
    public Collection getHardTokenIssuerDatas(Admin admin){
      log.trace(">getHardTokenIssuerDatas()");
      ArrayList returnval = new ArrayList();
      Collection result = null;
      HardTokenIssuerDataLocal htih = null;
      Collection authorizedhardtokenprofiles = this.getAuthorizedHardTokenProfileIds(admin);
      try{
        result = hardtokenissuerhome.findAll();
        if(result.size()>0){
          Iterator i = result.iterator();
          while(i.hasNext()){
            htih = (HardTokenIssuerDataLocal) i.next();
            if(authorizedhardtokenprofiles.containsAll(htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
              returnval.add(new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer()));
            }
          }
        }
        Collections.sort(returnval);
      }catch(FinderException e){}

      log.trace("<getHardTokenIssuerDatas()");
      return returnval;
    } // getHardTokenIssuers

      /**
       * Returns the available hard token issuer alliases authorized to the administrator.
       *
       * @return A collection of available hard token issuer aliases.
       * @throws EJBException if a communication or other error occurs.
       * @ejb.interface-method view-type="both"
       */
    public Collection getHardTokenIssuerAliases(Admin admin){
      log.trace(">getHardTokenIssuerAliases()");
      ArrayList returnval = new ArrayList();
      Collection result = null;
      Collection authorizedhardtokenprofiles = this.getAuthorizedHardTokenProfileIds(admin);
      HardTokenIssuerDataLocal htih = null;
      try{
        result = hardtokenissuerhome.findAll();
        if(result.size()>0){
          Iterator i = result.iterator();
          while(i.hasNext()){
            htih = (HardTokenIssuerDataLocal) i.next();
            if(authorizedhardtokenprofiles.containsAll(htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
              returnval.add(htih.getAlias());
            }
          }
        }
        Collections.sort(returnval);
      }catch(FinderException e){}

      log.trace("<getHardTokenIssuerAliases()");
      return returnval;
    }// getHardTokenIssuerAliases

      /**
       * Returns the available hard token issuers authorized to the administrator.
       *
       * @return A treemap of available hard token issuers.
       * @throws EJBException if a communication or other error occurs.
       * @ejb.interface-method view-type="both"
       */
    public TreeMap getHardTokenIssuers(Admin admin){
      log.trace(">getHardTokenIssuers()");
      Collection authorizedhardtokenprofiles = this.getAuthorizedHardTokenProfileIds(admin);
      TreeMap returnval = new TreeMap();
      Collection result = null;
      try{
        result = hardtokenissuerhome.findAll();
        if(result.size()>0){
          Iterator i = result.iterator();
          while(i.hasNext()){
            HardTokenIssuerDataLocal htih = (HardTokenIssuerDataLocal) i.next();
            if(authorizedhardtokenprofiles.containsAll(htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
              returnval.put(htih.getAlias(), new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer()));
            }
          }
        }
      }catch(FinderException e){}

      log.trace("<getHardTokenIssuers()");
      return returnval;
    } // getHardTokenIssuers

      /**
       * Returns the specified hard token issuer.
       *
       * @return the hard token issuer data or null if hard token issuer doesn't exists.
       * @throws EJBException if a communication or other error occurs.
       * @ejb.interface-method view-type="both"
       */
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, String alias){
		if (log.isTraceEnabled()) {
			log.trace(">getHardTokenIssuerData(alias: " + alias + ")");
		}
      HardTokenIssuerData returnval = null;
      HardTokenIssuerDataLocal htih = null;
      try{
        htih = hardtokenissuerhome.findByAlias(alias);
        if(htih != null){
          returnval = new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer());
        }
      }catch(FinderException e){}

      log.trace("<getHardTokenIssuerData()");
      return returnval;
    } // getHardTokenIssuerData

       /**
       * Returns the specified  hard token issuer.
       *
       * @return the  hard token issuer data or null if  hard token issuer doesn't exists.
       * @throws EJBException if a communication or other error occurs.
        * @ejb.interface-method view-type="both"
       */
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, int id){
		if (log.isTraceEnabled()) {
			log.trace(">getHardTokenIssuerData(id: " + id +")" );
		}
      HardTokenIssuerData returnval = null;
      HardTokenIssuerDataLocal htih = null;
      try{
        htih = hardtokenissuerhome.findByPrimaryKey(new Integer(id));
        if(htih != null){
          returnval = new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer());
        }
      }catch(FinderException e){}

      log.trace("<getHardTokenIssuerData()");
      return returnval;
    } // getHardTokenIssuerData


      /**
       * Returns the number of available hard token issuer.
       *
       * @return the number of available hard token issuer.
       * @throws EJBException if a communication or other error occurs.
       * @ejb.interface-method view-type="both"
       */
    public int getNumberOfHardTokenIssuers(Admin admin){
      trace(">getNumberOfHardTokenIssuers()");
      int returnval =0;
      try{
        returnval = (hardtokenissuerhome.findAll()).size();
      }catch(FinderException e){}

      trace("<getNumberOfHardTokenIssuers()");
      return returnval;
    } // getNumberOfHardTokenIssuers

      /**
       * Returns a hard token issuer id given its alias.
       *
       * @return id number of hard token issuer.
       * @throws EJBException if a communication or other error occurs.
       * @ejb.interface-method view-type="both"
       */
    public int getHardTokenIssuerId(Admin admin, String alias){
		if (log.isTraceEnabled()) {
			log.trace(">getHardTokenIssuerId(alias: " + alias + ")");
		}
      int returnval = NO_ISSUER;
      HardTokenIssuerDataLocal htih = null;
      try{
        htih = hardtokenissuerhome.findByAlias(alias);
        if(htih != null){
          returnval = htih.getId().intValue();
        }
      }catch(FinderException e){}

      log.trace("<getHardTokenIssuerId()");
      return returnval;
    } // getNumberOfHardTokenIssuersId

       /**
       * Returns a hard token issuer alias given its id.
       *
       * @return the alias or null if id noesnt exists
       * @throws EJBException if a communication or other error occurs.
        * @ejb.interface-method view-type="both"
       */
    public String getHardTokenIssuerAlias(Admin admin, int id){
		if (log.isTraceEnabled()) {
			log.trace(">getHardTokenIssuerAlias(id: " + id + ")");
		}
      String returnval = null;
      HardTokenIssuerDataLocal htih = null;
      try{
        htih = hardtokenissuerhome.findByPrimaryKey(new Integer(id));
        if(htih != null){
          returnval = htih.getAlias();
        }
      }catch(FinderException e){}

      log.trace("<getHardTokenIssuerAlias()");
      return returnval;
    } // getHardTokenIssuerAlias

        /**
       * Checks if a hard token profile is among a hard tokens issuers available token types.
       *
       * @param admin the administrator calling the function
       * @param issuerid the id of the issuer to check.
       * @param userdata the data of user about to be generated
       *
       * @throws UnavailableTokenException if users tokentype isn't among hard token issuers available tokentypes.
       * @throws EJBException if a communication or other error occurs.
         * @ejb.interface-method view-type="both"
       */

    public void getIsHardTokenProfileAvailableToIssuer(Admin admin, int issuerid, UserDataVO userdata) throws UnavailableTokenException{
		if (log.isTraceEnabled()) {
			log.trace(">getIsTokenTypeAvailableToIssuer(issuerid: " + issuerid + ", tokentype: " + userdata.getTokenType()+ ")");
		}
        boolean returnval = false;
        ArrayList availabletokentypes = getHardTokenIssuerData(admin, issuerid).getHardTokenIssuer().getAvailableHardTokenProfiles();

        for(int i=0; i < availabletokentypes.size(); i++){
          if(((Integer) availabletokentypes.get(i)).intValue() == userdata.getTokenType()) {
            returnval = true;
          }
        }

        if(!returnval) {
        	String msg = intres.getLocalizedMessage("hardtoken.unavailabletoken", userdata.getUsername());            	
        	throw new UnavailableTokenException(msg);
        }
        log.trace("<getIsTokenTypeAvailableToIssuer()");
    } // getIsTokenTypeAvailableToIssuer

       /**
       * Adds a hard token to the database
       *
       * @param admin the administrator calling the function
       * @param tokensn The serialnumber of token.
       * @param username the user owning the token.
       * @param significantissuerdn indicates which CA the hard token should belong to.
       * @param hardtokendata the hard token data
       * @param certificates  a collection of certificates places in the hard token
       * @param copyof indicates if the newly created token is a copy of an existing token. Use null if token is an original
       *
       * @throws EJBException if a communication or other error occurs.
       * @throws HardTokenExistsException if tokensn already exists in databas.
        * @ejb.interface-method view-type="both"
        * @ejb.transaction type="Required"
       */
    public void addHardToken(Admin admin, String tokensn, String username, String significantissuerdn, int tokentype,  HardToken hardtokendata, Collection certificates, String copyof) throws HardTokenExistsException{
		if (log.isTraceEnabled()) {
	        log.trace(">addHardToken(tokensn : " + tokensn + ")");
		}
		String bcdn = CertTools.stringToBCDNString(significantissuerdn);
    	boolean exists = false;
    	try {
        	// We must actually check if there is one before we try to add it, because wls does not allow us to catch any errors if creating fails, that sux
        	HardTokenDataLocal data = hardtokendatahome.findByPrimaryKey(tokensn);
        	if (data != null) {
        		exists = true;
        	}
    	} catch (FinderException e) {
    		// This is what we hope will happen
    	}
    	if (!exists) {
    		try {
    			hardtokendatahome.create(admin,tokensn, username,new java.util.Date(), new java.util.Date(), tokentype, bcdn, setHardToken(admin, getSignSession(), getRaAdminSession().loadGlobalConfiguration(admin).getHardTokenEncryptCA(), hardtokendata));
    			if(certificates != null){
    				Iterator i = certificates.iterator();
    				while(i.hasNext()){
    					addHardTokenCertificateMapping(admin, tokensn, (X509Certificate) i.next());
    				}
    			}
    			if(copyof != null){
    				hardtokenpropertyhome.create(tokensn, HardTokenPropertyEntityBean.PROPERTY_COPYOF,copyof);
    			}
    			String msg = intres.getLocalizedMessage("hardtoken.addedtoken", tokensn);            	
    			getLogSession().log(admin, bcdn.hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),username, null, LogConstants.EVENT_INFO_HARDTOKENDATA,msg);
    		}
    		catch (Exception e) {
    			String msg = intres.getLocalizedMessage("hardtoken.tokenexists", tokensn);            	
    			getLogSession().log(admin, bcdn.hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),username, null, LogConstants.EVENT_ERROR_HARDTOKENDATA,msg);
    			throw new HardTokenExistsException("Tokensn : " + tokensn);
    		}
    	} else {
    		String msg = intres.getLocalizedMessage("hardtoken.tokenexists", tokensn);            	
    		getLogSession().log(admin, bcdn.hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),username, null, LogConstants.EVENT_ERROR_HARDTOKENDATA,msg);
    		throw new HardTokenExistsException("Tokensn : " + tokensn);    		
    	}
        log.trace("<addHardToken()");
    } // addHardToken

       /**
       * changes a hard token data in the database
       *
       * @param admin the administrator calling the function
       * @param tokensn The serialnumber of token.
       * @param hardtokendata the hard token data
       *
       * @throws EJBException if a communication or other error occurs.
       * @throws HardTokenDoesntExistsException if tokensn doesn't exists in databas.
        * @ejb.interface-method view-type="both"
        * @ejb.transaction type="Required"
       */
    public void changeHardToken(Admin admin, String tokensn, int tokentype, HardToken hardtokendata) throws HardTokenDoesntExistsException{
		if (log.isTraceEnabled()) {
	        log.trace(">changeHardToken(tokensn : " + tokensn + ")");
		}
        int caid = LogConstants.INTERNALCAID;
        try {
            HardTokenDataLocal htd = hardtokendatahome.findByPrimaryKey(tokensn);
            htd.setTokenType(tokentype);
            htd.setData(setHardToken(admin,getSignSession(),getRaAdminSession().loadGlobalConfiguration(admin).getHardTokenEncryptCA(),hardtokendata));
            htd.setModifyTime(new java.util.Date());
            caid = htd.getSignificantIssuerDN().hashCode();
        	String msg = intres.getLocalizedMessage("hardtoken.changedtoken", tokensn);            	
            getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),htd.getUsername(), null, LogConstants.EVENT_INFO_HARDTOKENDATA,msg);
        }
        catch (Exception e) {
        	String msg = intres.getLocalizedMessage("hardtoken.errorchangetoken", tokensn);            	
        	getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENDATA,msg);
        	throw new HardTokenDoesntExistsException("Tokensn : " + tokensn);
        }
        log.trace("<changeHardToken()");
    } // changeHardToken

       /**
       * removes a hard token data from the database
       *
       * @param admin the administrator calling the function
       * @param tokensn The serialnumber of token.
       *
       * @throws EJBException if a communication or other error occurs.
       * @throws HardTokenDoesntExistsException if tokensn doesn't exists in databas.
        * @ejb.interface-method view-type="both"
        * @ejb.transaction type="Required"
       */
    public void removeHardToken(Admin admin, String tokensn) throws HardTokenDoesntExistsException{
		if (log.isTraceEnabled()) {
			log.trace(">removeHardToken(tokensn : " + tokensn + ")");
		}
      int caid = LogConstants.INTERNALCAID;
      try{
        HardTokenDataLocal htd = hardtokendatahome.findByPrimaryKey(tokensn);
        caid = htd.getSignificantIssuerDN().hashCode();
        htd.remove();

        // Remove all certificate mappings.
        removeHardTokenCertificateMappings(admin, tokensn);


        // Remove all copyof references id property database.
       try{
        	hardtokenpropertyhome.findByProperty(tokensn, HardTokenPropertyEntityBean.PROPERTY_COPYOF).remove();
        }catch(FinderException fe){}
        try{
          Collection copieslocal = hardtokenpropertyhome.findIdsByPropertyAndValue(HardTokenPropertyEntityBean.PROPERTY_COPYOF , tokensn);
          Iterator iter = copieslocal.iterator();
          while(iter.hasNext()){
        	 ((HardTokenPropertyLocal) iter.next()).remove();
           }
        }catch(FinderException fe){}
    	String msg = intres.getLocalizedMessage("hardtoken.removedtoken", tokensn);            	
        getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENDATA,msg);
      }catch(Exception e){
    	  String msg = intres.getLocalizedMessage("hardtoken.errorremovetoken", tokensn);            	
    	  getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENDATA,msg);
    	  throw new HardTokenDoesntExistsException("Tokensn : " + tokensn);
      }
      log.trace("<removeHardToken()");
    } // removeHardToken

       /**
       * Checks if a hard token serialnumber exists in the database
       *
       * @param admin the administrator calling the function
       * @param tokensn The serialnumber of token.
       *
       * @return true if it exists or false otherwise.
       * @throws EJBException if a communication or other error occurs.
        * @ejb.interface-method view-type="both"
       */
    public boolean existsHardToken(Admin admin, String tokensn){
		if (log.isTraceEnabled()) {
			log.trace(">existsHardToken(tokensn : " + tokensn + ")");
		}
       boolean ret = false;
        try {
            hardtokendatahome.findByPrimaryKey(tokensn);
            ret = true;
        } catch (javax.ejb.FinderException fe) {
             ret=false;
        } catch(Exception e){
          throw new EJBException(e);
        }
       log.trace("<existsHardToken()");
       return ret;
    } // existsHardToken

      /**
       * returns hard token data for the specified tokensn
       *
       * @param admin the administrator calling the function
       * @param tokensn The serialnumber of token.
       *
       * @return the hard token data or NULL if tokensn doesnt exists in database.
       * @throws EJBException if a communication or other error occurs.
       * @ejb.interface-method view-type="both"
       */
    public HardTokenData getHardToken(Admin admin, String tokensn, boolean includePUK) throws AuthorizationDeniedException{
		if (log.isTraceEnabled()) {
			log.trace("<getHardToken(tokensn :" + tokensn +")");
		}
       HardTokenData returnval = null;
       HardTokenDataLocal htd = null;
       try{
         htd = hardtokendatahome.findByPrimaryKey(tokensn);

         // Find Copyof
         String copyof = null;
         try{
         	copyof = hardtokenpropertyhome.findByProperty(tokensn, HardTokenPropertyEntityBean.PROPERTY_COPYOF).getValue();
         }catch(FinderException fe){}

         ArrayList copies = null;
         if(copyof == null){
           //  Find Copies
	  	   try{
             Collection copieslocal = hardtokenpropertyhome.findIdsByPropertyAndValue(HardTokenPropertyEntityBean.PROPERTY_COPYOF , tokensn);
             if(copieslocal.size() >0 ){
               copies = new ArrayList();
		       Iterator iter = copieslocal.iterator();
               while(iter.hasNext()){
           	      copies.add(((HardTokenPropertyLocal) iter.next()).getId());
               }
             }
		   }catch(FinderException fe){}
         }

         if(htd != null){
           returnval = new HardTokenData(htd.getTokenSN(),htd.getUsername(), htd.getCreateTime(),htd.getModifyTime(),htd.getTokenType(),htd.getSignificantIssuerDN(),getHardToken(admin,getSignSession(),getRaAdminSession().loadGlobalConfiguration(admin).getHardTokenEncryptCA(),includePUK,htd.getData()), copyof, copies);
           String msg = intres.getLocalizedMessage("hardtoken.viewedtoken", tokensn);            	
           getLogSession().log(admin, htd.getSignificantIssuerDN().hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),htd.getUsername(), null, LogConstants.EVENT_INFO_HARDTOKENVIEWED,msg);
           if(includePUK){
               msg = intres.getLocalizedMessage("hardtoken.viewedpuk", tokensn);            	
               getLogSession().log(admin, htd.getSignificantIssuerDN().hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),htd.getUsername(), null, LogConstants.EVENT_INFO_PUKVIEWED,msg);        	   
           }
         }
       }catch(FinderException e){}

       log.trace("<getHardToken()");
       return returnval;
    } // getHardToken

      /**
       * returns hard token data for the specified user
       *
       * @param admin the administrator calling the function
       * @param username The username owning the tokens.
       *
       * @return a Collection of all hard token user data.
       * @throws EJBException if a communication or other error occurs.
       * @ejb.interface-method view-type="both"
       */
    public Collection getHardTokens(Admin admin, String username, boolean includePUK){
		if (log.isTraceEnabled()) {
			log.trace("<getHardToken(username :" + username +")");
		}
       ArrayList returnval = new ArrayList();
       HardTokenDataLocal htd = null;
       try{
         Collection result = hardtokendatahome.findByUsername(username);
         Iterator i = result.iterator();
         while(i.hasNext()){
           htd = (HardTokenDataLocal) i.next();
           // Find Copyof
           String copyof = null;
           try{
           	copyof = hardtokenpropertyhome.findByProperty(htd.getTokenSN(), HardTokenPropertyEntityBean.PROPERTY_COPYOF).getValue();
           }catch(FinderException fe){}


           ArrayList copies = null;
           if(copyof == null){
           	//  Find Copies
           	 try{
           		Collection copieslocal = hardtokenpropertyhome.findIdsByPropertyAndValue(HardTokenPropertyEntityBean.PROPERTY_COPYOF , htd.getTokenSN());
           		if(copieslocal.size() >0 ){
           			copies = new ArrayList();
           			Iterator iter = copieslocal.iterator();
           			while(iter.hasNext()){
           				copies.add(((HardTokenPropertyLocal) iter.next()).getId());
           			}
           		}
           	 }catch(FinderException fe){}
           }

           returnval.add(new HardTokenData(htd.getTokenSN(),htd.getUsername(), htd.getCreateTime(),htd.getModifyTime(),htd.getTokenType(),htd.getSignificantIssuerDN(),getHardToken(admin,getSignSession(),getRaAdminSession().loadGlobalConfiguration(admin).getHardTokenEncryptCA(), includePUK, htd.getData()),copyof, copies));
           String msg = intres.getLocalizedMessage("hardtoken.viewedtoken", htd.getTokenSN());            	
           getLogSession().log(admin, htd.getSignificantIssuerDN().hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),htd.getUsername(), null, LogConstants.EVENT_INFO_HARDTOKENVIEWED,msg);
           if(includePUK){
               msg = intres.getLocalizedMessage("hardtoken.viewedpuk", htd.getTokenSN());            	
               getLogSession().log(admin, htd.getSignificantIssuerDN().hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(),htd.getUsername(), null, LogConstants.EVENT_INFO_PUKVIEWED,msg);        	   
           }
         }
       }catch(FinderException e){}

       log.trace("<getHardToken()");
       return returnval;
    } // getHardTokens

    /**
     *  Method that searches the database for a tokensn. It returns all hardtokens
     * with a serialnumber that begins with the given searchpattern.
     *
     *  @param admin the administrator calling the function
     *  @param searchpattern of begining of hard token sn
     *  @return a Collection of username(String) matching the search string
     * @ejb.interface-method view-type="both"
     */

    public Collection findHardTokenByTokenSerialNumber(Admin admin, String searchpattern){
    	trace(">findHardTokenByTokenSerialNumber()");
    	ArrayList returnval = new ArrayList();
    	Connection con = null;
    	PreparedStatement ps = null;
    	ResultSet rs = null;
    	try{
    		// Construct SQL query.
    		con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
    		ps = con.prepareStatement("select distinct username from HardTokenData where  tokenSN LIKE '%" + searchpattern + "%'");
    		// Execute query.
    		rs = ps.executeQuery();
    		// Assemble result.
    		while(rs.next() && returnval.size() <= UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT){
    			returnval.add(rs.getString(1));
    		}
    		trace("<findHardTokenByTokenSerialNumber()");
    		return returnval;

    	}catch(Exception e){
    		throw new EJBException(e);
    	}finally{
            JDBCUtil.close(con, ps, rs);
    	}

    }

       /**
       * Adds a mapping between a hard token and a certificate
       *
       * @param admin the administrator calling the function
       * @param tokensn The serialnumber of token.
       * @param certificate the certificate to map to.
       *
       * @throws EJBException if a communication or other error occurs.
        * @ejb.interface-method view-type="both"
        * @ejb.transaction type="Required"
       */
    public void addHardTokenCertificateMapping(Admin admin, String tokensn, Certificate certificate){
        String certificatesn = CertTools.getSerialNumberAsString(certificate);
        if (log.isTraceEnabled()) {
            log.trace(">addHardTokenCertificateMapping(certificatesn : "+ certificatesn  +", tokensn : " + tokensn + ")");
        }
        int caid = CertTools.getIssuerDN(certificate).hashCode();
        String fp = CertTools.getFingerprintAsString(certificate);
        boolean exists = false;
        try {
        	// We must actually check if there is one before we try to add it, because wls does not allow us to catch any errors if creating fails, that sux
        	HardTokenCertificateMapLocal data = hardtokencertificatemaphome.findByPrimaryKey(fp);
        	if (data != null) {
        		exists = true;
        	}
        } catch (FinderException e) {
        	// This is what we hope will happen
        }
        if (!exists) {
        	try {
        		hardtokencertificatemaphome.create(fp,tokensn);
        		String msg = intres.getLocalizedMessage("hardtoken.addedtokencertmapping", certificatesn, tokensn);
        		getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENCERTIFICATEMAP,msg);
        	} catch (Exception e) {
        		String msg = intres.getLocalizedMessage("hardtoken.erroraddtokencertmapping", certificatesn, tokensn);
        		getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENCERTIFICATEMAP,msg);
        	}
        } else {
    		String msg = intres.getLocalizedMessage("hardtoken.erroraddtokencertmapping", certificatesn, tokensn);
    		getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENCERTIFICATEMAP,msg);        	
        }
        log.trace("<addHardTokenCertificateMapping()");
    } // addHardTokenCertificateMapping

      /**
       * Removes a mapping between a hard token and a certificate
       *
       * @param admin the administrator calling the function
       * @param certificate the certificate to map to.
       *
       *
       * @throws EJBException if a communication or other error occurs.
       * @ejb.interface-method view-type="both"
       * @ejb.transaction type="Required"
       */
    public void removeHardTokenCertificateMapping(Admin admin, Certificate certificate){
       String certificatesn = CertTools.getSerialNumberAsString(certificate);
       if (log.isTraceEnabled()) {
           log.trace(">removeHardTokenCertificateMapping(Certificatesn: " + certificatesn + ")");
       }
	   int caid = CertTools.getIssuerDN(certificate).hashCode();
      try{
        HardTokenCertificateMapLocal htcm =hardtokencertificatemaphome.findByPrimaryKey(CertTools.getFingerprintAsString(certificate));
        htcm.remove();
        String msg = intres.getLocalizedMessage("hardtoken.removedtokencertmappingcert", certificatesn);
        getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENCERTIFICATEMAP, msg);
      }catch(Exception e){
    	  try{
    		  String msg = intres.getLocalizedMessage("hardtoken.errorremovetokencertmappingcert", certificatesn);
    		  getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENCERTIFICATEMAP, msg);
    	  }catch(Exception re){
            throw new EJBException(e);
         }
      }
      log.trace("<removeHardTokenCertificateMapping()");
    } // removeHardTokenCertificateMapping


    /**
     * Removes all mappings between a hard token and a certificate
     *
     * @param admin the administrator calling the function
     * @param tokensn the serial number to remove.
     *
     *
     * @throws EJBException if a communication or other error occurs.
     */
    private void removeHardTokenCertificateMappings(Admin admin, String tokensn){
        if (log.isTraceEnabled()) {
        	log.trace(">removeHardTokenCertificateMappings(tokensn: " + tokensn + ")");
        }
	  int caid = admin.getCaId();
      try{
      	Iterator result = hardtokencertificatemaphome.findByTokenSN(tokensn).iterator();
      	while(result.hasNext()){
          HardTokenCertificateMapLocal htcm = (HardTokenCertificateMapLocal) result.next();
          htcm.remove();

      	}
        String msg = intres.getLocalizedMessage("hardtoken.removedtokencertmappingtoken", tokensn);
        getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_INFO_HARDTOKENCERTIFICATEMAP, msg);
        }catch(Exception e){
        	try{
        		String msg = intres.getLocalizedMessage("hardtoken.errorremovetokencertmappingtoken", tokensn);
        		getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_HARDTOKENCERTIFICATEMAP, msg);
        	}catch(Exception re){
              throw new EJBException(e);
           }
         }
         log.trace("<removeHardTokenCertificateMappings()");
     } // removeHardTokenCertificateMapping

       /**
       * Returns all the X509Certificates places in a hard token.
       *
       * @param admin the administrator calling the function
       * @param tokensn The serialnumber of token.
       *
       * @return a collection of X509Certificates
       * @throws EJBException if a communication or other error occurs.
        * @ejb.interface-method view-type="both"
       */
    public Collection findCertificatesInHardToken(Admin admin, String tokensn){
    	if (log.isTraceEnabled()) {
        	log.trace("<findCertificatesInHardToken(username :" + tokensn +")");
        }
       ArrayList returnval = new ArrayList();
       HardTokenCertificateMapLocal htcm = null;
       try{
         Collection result = hardtokencertificatemaphome.findByTokenSN(tokensn);         
         Iterator i = result.iterator();
         while(i.hasNext()){
           htcm = (HardTokenCertificateMapLocal) i.next();
           Certificate cert = getCertificateStoreSession().findCertificateByFingerprint(admin, htcm.getCertificateFingerprint());
           if (cert != null) {
               returnval.add(cert);
           }
         }
       }catch(Exception e){
          throw new EJBException(e);
       }

       log.trace("<findCertificatesInHardToken()");
       return returnval;
    } // findCertificatesInHardToken

    /**
     * Returns the tokensn that the have blongs to a given certificatesn and tokensn.
     *
     * @param admin the administrator calling the function
     * @param certificatesn The serialnumber of certificate.
     * @param issuerdn the issuerdn of the certificate.
     *
     * @return the serialnumber or null if no tokensn could be found.
     * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method view-type="both"
     */
  public String findHardTokenByCertificateSNIssuerDN(Admin admin, BigInteger certificatesn, String issuerdn){
	  if (log.isTraceEnabled()) {
		  log.trace("<findHardTokenByCertificateSNIssuerDN(certificatesn :" + certificatesn + ", issuerdn :" + issuerdn+ ")");
	  }
     String returnval = null;
     HardTokenCertificateMapLocal htcm = null;
     try{
       X509Certificate cert = (X509Certificate) getCertificateStoreSession().findCertificateByIssuerAndSerno(admin,issuerdn,certificatesn);
       if(cert != null){       	       	 
         htcm = hardtokencertificatemaphome.findByPrimaryKey(CertTools.getFingerprintAsString(cert));        
         if(htcm != null){
           returnval = htcm.getTokenSN();
         }
       }
     }catch(Exception e){
        throw new EJBException(e);
     }

     log.trace("<findHardTokenByCertificateSNIssuerDN()");
     return returnval;
  } // findCertificatesInHardToken
    

    /**
     * Method used to signal to the log that token was generated successfully.
     *
     * @param admin administrator performing action
     * @param tokensn tokensn of token generated
     * @param username username of user token was generated for.
     * @param significantissuerdn indicates which CA the hard token should belong to.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    public void tokenGenerated(Admin admin, String tokensn, String username, String significantissuerdn){
	  int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode();
      try{
  		String msg = intres.getLocalizedMessage("hardtoken.generatedtoken", tokensn);
        getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),username, null, LogConstants.EVENT_INFO_HARDTOKENGENERATED, msg);
      }catch(Exception e){
        throw new EJBException(e);
      }
    } // tokenGenerated

    /**
     * Method used to signal to the log that error occured when generating token.
     *
     * @param admin administrator performing action
     * @param tokensn tokensn of token.
     * @param username username of user token was generated for.
     * @param significantissuerdn indicates which CA the hard token should belong to.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    public void errorWhenGeneratingToken(Admin admin, String tokensn, String username, String significantissuerdn){
      int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode();
      try{
    	  String msg = intres.getLocalizedMessage("hardtoken.errorgeneratetoken", tokensn);
    	  getLogSession().log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(),username, null, LogConstants.EVENT_ERROR_HARDTOKENGENERATED, msg);
      }catch(Exception e){
        throw new EJBException(e);
      }
    } // errorWhenGeneratingToken


	/**
	* Method to check if a certificate profile exists in any of the hard token profiles.
	* Used to avoid desyncronization of certificate profile data.
	*
	* @param id the certificateprofileid to search for.
	* @return true if certificateprofileid exists in any of the hard token profiles.
     * @ejb.interface-method view-type="both"
	*/
   public boolean existsCertificateProfileInHardTokenProfiles(Admin admin, int id){
   	 HardTokenProfile profile = null;
	 Collection certprofiles=null;
	 boolean exists = false;
	 try{
	   Collection result = hardtokenprofilehome.findAll();
	   Iterator i = result.iterator();
	   while(i.hasNext() && !exists){
		 profile = getHardTokenProfile((HardTokenProfileDataLocal) i.next());
		 if(profile instanceof EIDProfile){
		   certprofiles = ((EIDProfile) profile).getAllCertificateProfileIds();
		   if(certprofiles.contains(new Integer(id))) {
		     exists = true;
		   }
		 }
	   }
	 }catch(FinderException e){}

	 return exists;
   } // existsCertificateProfileInHardTokenProfiles
   
	/**
	* Method to check if a hard token profile exists in any of the hard token issuers.
	* Used to avoid desyncronization of hard token profile data.
	*
	* @param id the hard token profileid to search for.
	* @return true if hard token profileid exists in any of the hard token issuers.
    * @ejb.interface-method view-type="both"
	*/
  public boolean existsHardTokenProfileInHardTokenIssuer(Admin admin, int id){
  	 HardTokenIssuer issuer = null;
	 Collection hardtokenissuers=null;
	 boolean exists = false;
	 try{
	   Collection result = this.hardtokenissuerhome.findAll();
	   Iterator i = result.iterator();
	   while(i.hasNext() && !exists){
		 issuer = ((HardTokenIssuerDataLocal) i.next()).getHardTokenIssuer();
		 hardtokenissuers = issuer.getAvailableHardTokenProfiles();
		 if(hardtokenissuers.contains(new Integer(id))) {
			 exists = true;		 
		 }
	   }
	 }catch(FinderException e){}
	 return exists;
  } // existsHardTokenProfileInHardTokenIssuer

	private Integer findFreeHardTokenProfileId(){
	  Random ran = (new Random((new Date()).getTime()));
	  int id = ran.nextInt();
	  boolean foundfree = false;

	  while(!foundfree){
		try{
		  if(id > SecConst.TOKEN_SOFT) {
			  // This will throw if nothing with this id is found in database
			hardtokenprofilehome.findByPrimaryKey(new Integer(id));
		  }
		  id = ran.nextInt();
		}catch(FinderException e){
		   foundfree = true;
		}
	  }
	  return new Integer(id);
	} // findFreeHardTokenProfileId

    private Integer findFreeHardTokenIssuerId(){
      Random ran = (new Random((new Date()).getTime()));
      int id = ran.nextInt();
      boolean foundfree = false;

      while(!foundfree){
        try{
          if(id > 1) {
        	// This will throw if id is not found  
            hardtokenissuerhome.findByPrimaryKey(new Integer(id));
          }
          id = ran.nextInt();
        }catch(FinderException e){
           foundfree = true;
        }
      }
      return new Integer(id);
    } // findFreeHardTokenIssuerId

    
    private static final String ENCRYPTEDDATA = "ENCRYPTEDDATA";
     /**
     * Method that returns the hard token data from a hashmap and updates it if nessesary.
     */
    private HardToken getHardToken(Admin admin, ISignSessionLocal signsession, int encryptcaid, boolean includePUK, HashMap data){
      HardToken returnval = null;      
      
      if(data.get(ENCRYPTEDDATA) != null){
    	  // Data in encrypted, decrypt
    	  byte[] encdata = (byte[]) data.get(ENCRYPTEDDATA);
    	  
    	  HardTokenEncryptCAServiceRequest request = new HardTokenEncryptCAServiceRequest(HardTokenEncryptCAServiceRequest.COMMAND_DECRYPTDATA,encdata);
    	  try {
    		HardTokenEncryptCAServiceResponse response = (HardTokenEncryptCAServiceResponse) signsession.extendedService(admin, encryptcaid, request);
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(response.getData()));
			data = (HashMap) ois.readObject();
		} catch (Exception e) {
			throw new EJBException(e);
		}
      }      
      
      int tokentype = ((Integer) data.get(HardToken.TOKENTYPE)).intValue();

      switch(tokentype){
          case SecConst.TOKEN_SWEDISHEID :
      	     returnval = new SwedishEIDHardToken(includePUK);
      	     break;
          case SecConst.TOKEN_ENHANCEDEID :
      	     returnval = new EnhancedEIDHardToken(includePUK);
      	     break;
          case SecConst.TOKEN_TURKISHEID :
       	     returnval = new TurkishEIDHardToken(includePUK);
       	     break;
          case SecConst.TOKEN_EID :    // Left for backward compability
             returnval = new EIDHardToken(includePUK);
             break;
          default:
             returnval = new EIDHardToken(includePUK);
             break;
      }

      returnval.loadData(data);
      return returnval;
    }

    /**
     * Method that saves the hard token issuer data to a HashMap that can be saved to database.
     */
    private HashMap setHardToken(Admin admin, ISignSessionLocal signsession, int encryptcaid, HardToken tokendata){
    	HashMap retval = null;
    	if(encryptcaid != 0){
    		try {
    			ByteArrayOutputStream baos = new ByteArrayOutputStream();    	   
    			ObjectOutputStream ois = new ObjectOutputStream(baos);
    			ois.writeObject(tokendata.saveData());
    			HardTokenEncryptCAServiceRequest request = new HardTokenEncryptCAServiceRequest(HardTokenEncryptCAServiceRequest.COMMAND_ENCRYPTDATA,baos.toByteArray());
    			HardTokenEncryptCAServiceResponse response = (HardTokenEncryptCAServiceResponse) signsession.extendedService(admin, encryptcaid, request);
    			HashMap data = new HashMap();
    			data.put(ENCRYPTEDDATA, response.getData());
    			retval = data;
    		} catch (Exception e) {
    			new EJBException(e);
    		}
    	}else{
    		// Don't encrypt data
    		retval = (HashMap) tokendata.saveData();
    	}
    	
    	return retval;
    }
    
	private HardTokenProfile getHardTokenProfile(HardTokenProfileDataLocal htpData) {
		HardTokenProfile profile = null;
		java.beans.XMLDecoder decoder;
		try {
			decoder = new java.beans.XMLDecoder(
					new java.io.ByteArrayInputStream(htpData.getData().getBytes("UTF8")));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
		HashMap h = (HashMap) decoder.readObject();
		decoder.close();
		// Handle Base64 encoded string values
		HashMap data = new Base64GetHashMap(h);
		switch (((Integer) (data.get(HardTokenProfile.TYPE))).intValue()) {
		case SwedishEIDProfile.TYPE_SWEDISHEID :
			profile = new SwedishEIDProfile();
			break;
		case EnhancedEIDProfile.TYPE_ENHANCEDEID:
			profile =  new EnhancedEIDProfile();
			break;
		case TurkishEIDProfile.TYPE_TURKISHEID :
			profile =  new TurkishEIDProfile();
			break;            
		}
		profile.loadData(data);
		return profile;
	}

    /**
     * Method that saves the hard token profile data to database.
     *
	private void setHardTokenProfile(HardTokenProfileDataLocal htpData, HardTokenProfile hardtokenprofile){
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap)hardtokenprofile.saveData());
        
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
		java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
		encoder.writeObject(a);
		encoder.close();

		try {
            if (log.isDebugEnabled()) {
            	if (baos.size() < 10000) {
                    log.debug("Profiledata: \n" + baos.toString("UTF8"));            		
            	} else {
            		log.debug("Profiledata larger than 10000 bytes, not displayed.");
            	}
            }
            htpData.setData(baos.toString("UTF8"));
		} catch (UnsupportedEncodingException e) {
          throw new EJBException(e);
		}

		htpData.setUpdateCounter(htpData.getUpdateCounter() +1);
    }*/

} // LocalHardTokenSessionBean
