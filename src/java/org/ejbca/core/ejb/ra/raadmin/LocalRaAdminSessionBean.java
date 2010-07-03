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

package org.ejbca.core.ejb.ra.raadmin;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;


/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id$
 *
 * @ejb.bean description="Session bean handling core CA function,signing certificates"
 *   display-name="RaAdminSB"
 *   name="RaAdminSession"
 *   jndi-name="RaAdminSession"
 *   local-jndi-name="RaAdminSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   remote-class="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   remote-class="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal"
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref description="The Authorization session bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *
 * @ejb.ejb-external-ref description="The AdminPreferencesData Entity bean"
 *   view-type="local"
 *   ref-name="ejb/AdminPreferencesDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ra.raadmin.AdminPreferencesDataLocalHome"
 *   business="org.ejbca.core.ejb.ra.raadmin.AdminPreferencesDataLocal"
 *   link="AdminPreferencesData"
 *
 * @ejb.ejb-external-ref description="The EndEntityProfileData Entity bean"
 *   view-type="local"
 *   ref-name="ejb/EndEntityProfileDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ra.raadmin.EndEntityProfileDataLocalHome"
 *   business="org.ejbca.core.ejb.ra.raadmin.EndEntityProfileDataLocal"
 *   link="EndEntityProfileData"
 *
 * @ejb.ejb-external-ref description="The GlobalConfigurationData Entity bean"
 *   view-type="local"
 *   ref-name="ejb/GlobalConfigurationDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ra.raadmin.GlobalConfigurationDataLocalHome"
 *   business="org.ejbca.core.ejb.ra.raadmin.GlobalConfigurationDataLocal"
 *   link="GlobalConfigurationData"
 *
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @jboss.method-attributes
 *   pattern = "get*"
 *   read-only = "true"
 *
 * @jboss.method-attributes
 *   pattern = "is*"
 *   read-only = "true"
 *   
 * @jboss.method-attributes
 *   pattern = "exists*"
 *   read-only = "true"
 *
 */
public class LocalRaAdminSessionBean extends BaseSessionBean  {

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** The home interface of  AdminPreferences entity bean */
    private AdminPreferencesDataLocalHome adminpreferenceshome=null;

    /** The home interface of  EndEntityProfileData entity bean */
    private EndEntityProfileDataLocalHome profiledatahome=null;

    /** The home interface of  GlobalConfiguration entity bean */
    private GlobalConfigurationDataLocalHome globalconfigurationhome = null;

    /** Cache variable containing the global configuration. */
    private GlobalConfiguration globalconfiguration = null;
    /** Constant indicating minimum time between updates of the global configuration cache. In milliseconds, 30 seconds. */
    private static final long MIN_TIME_BETWEEN_GLOBCONF_UPDATES = 30000;
    /** help variable used to control that update isn't performed to often. */
    private long lastupdatetime = -1;

    /** The local interface of  log session bean */
    private ILogSessionLocal logsession = null;
    private ICAAdminSessionLocal caAdminSession;

    /** the local inteface of authorization session */
    private IAuthorizationSessionLocal authorizationsession = null;


    public static final String EMPTY_ENDENTITYPROFILENAME   = "EMPTY";

    private static final String DEFAULTUSERPREFERENCE = "default";

    public static final String EMPTY_ENDENTITYPROFILE = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILENAME;
    public static final int EMPTY_ENDENTITYPROFILEID  = SecConst.EMPTY_ENDENTITYPROFILE;

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     * @ejb.create-method
     */
    public void ejbCreate() throws CreateException {
      try{
        adminpreferenceshome = (AdminPreferencesDataLocalHome)getLocator().getLocalHome(AdminPreferencesDataLocalHome.COMP_NAME);
        profiledatahome = (EndEntityProfileDataLocalHome)getLocator().getLocalHome(EndEntityProfileDataLocalHome.COMP_NAME);
        globalconfigurationhome = (GlobalConfigurationDataLocalHome)getLocator().getLocalHome(GlobalConfigurationDataLocalHome.COMP_NAME);
        
      }catch(Exception e){
         throw new EJBException(e);
      }

    }


    /** Gets connection to log session bean
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


    /** Gets connection to authorization session bean
     * @return Connection
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

     /**
     * Finds the admin preference belonging to a certificate serialnumber. Returns null if admin doesn't exists.
     * @ejb.interface-method
     */
    public AdminPreference getAdminPreference(Admin admin, String certificatefingerprint){
    	if (log.isTraceEnabled()) {
    		trace(">getAdminPreference()");
    	}
        AdminPreference ret =null;
        try {
            AdminPreferencesDataLocal apdata = adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
            ret = apdata.getAdminPreference();
        } catch (javax.ejb.FinderException fe) {
             // Create new configuration
             ret=null;
        } catch(Exception e){
          throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		trace("<getAdminPreference()");
    	}
        return ret;
    } // getAdminPreference

    /**
     * Adds a admin preference to the database. Returns false if admin already exists.
     * @ejb.interface-method
     */
    public boolean addAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference){
    	if (log.isTraceEnabled()) {
        	log.trace(">addAdminPreference(fingerprint : " + certificatefingerprint + ")");
    	}
    	boolean ret = false;
    	boolean exists = false;
    	try {
        	// We must actually check if there is one before we try to add it, because wls does not allow us to catch any errors if creating fails, that sux
        	AdminPreferencesDataLocal data = adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
        	if (data != null) {
        		exists = true;
        	}
    	} catch (FinderException e) {
    		// This is what we hope will happen
    	}
    	if (!exists) {
    		try {
    			AdminPreferencesDataLocal apdata= adminpreferenceshome.create(certificatefingerprint, adminpreference);
    			String msg = intres.getLocalizedMessage("ra.adminprefadded", apdata.getId());            	
    			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED,msg);
    			ret = true;        		
    		} catch (Exception e) {
    			ret = false;
    			String msg = intres.getLocalizedMessage("ra.adminprefexists");            	
    			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED,msg);
    		}
    	} else {
    		ret = false;
    		String msg = intres.getLocalizedMessage("ra.adminprefexists");            	
    		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED,msg);            	        		
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<addAdminPreference()");
    	}
    	return ret;
    } // addAdminPreference

    /**
     * Changes the admin preference in the database. Returns false if admin doesn't exists.
     * @ejb.interface-method
     */
    public boolean changeAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference){
    	if (log.isTraceEnabled()) {
    		log.trace(">changeAdminPreference(fingerprint : " + certificatefingerprint + ")");
    	}
    	return updateAdminPreference(admin, certificatefingerprint, adminpreference, true);
    } // changeAdminPreference

    /**
     * Changes the admin preference in the database. Returns false if admin doesn't exists.
     * @ejb.interface-method
     */
    public boolean changeAdminPreferenceNoLog(Admin admin, String certificatefingerprint, AdminPreference adminpreference){
    	if (log.isTraceEnabled()) {
    		log.trace(">changeAdminPreferenceNoLog(fingerprint : " + certificatefingerprint + ")");
    	}
    	return updateAdminPreference(admin, certificatefingerprint, adminpreference, false);
    } // changeAdminPreference

    /**
     * Checks if a admin preference exists in the database.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public boolean existsAdminPreference(Admin admin, String certificatefingerprint){
    	if (log.isTraceEnabled()) {
    	    log.trace(">existsAdminPreference(fingerprint : " + certificatefingerprint + ")");
    	}
       boolean ret = false;
        try {
            AdminPreferencesDataLocal apdata = adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
            debug("Found admin preferences with id "+apdata.getId());
            ret = true;
        } catch (javax.ejb.FinderException fe) {
             ret=false;
        } catch(Exception e){
          throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<existsAdminPreference()");
    	}
        return ret;
    }// existsAdminPreference

    /**
     * Function that returns the default admin preference.
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public AdminPreference getDefaultAdminPreference(Admin admin){
    	if (log.isTraceEnabled()) {
    		trace(">getDefaultAdminPreference()");
    	}
        AdminPreference ret =null;
        try {
            AdminPreferencesDataLocal apdata = adminpreferenceshome.findByPrimaryKey(DEFAULTUSERPREFERENCE);
            ret = apdata.getAdminPreference();
        } catch (javax.ejb.FinderException fe) {
            try{
               // Create new configuration
              AdminPreferencesDataLocal apdata = adminpreferenceshome.create(DEFAULTUSERPREFERENCE,new AdminPreference());
              ret = apdata.getAdminPreference();
            }catch(Exception e){
              throw new EJBException(e);
            }
        } catch(Exception e){
          throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		trace("<getDefaultAdminPreference()");
    	}
        return ret;
    } // getDefaultPreference()

     /**
     * Function that saves the default admin preference.
     *
     * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method
     */
    public void saveDefaultAdminPreference(Admin admin, AdminPreference defaultadminpreference){
    	if (log.isTraceEnabled()) {
    		trace(">saveDefaultAdminPreference()");
    	}
       try {
          AdminPreferencesDataLocal apdata = adminpreferenceshome.findByPrimaryKey(DEFAULTUSERPREFERENCE);
          apdata.setAdminPreference(defaultadminpreference);
          String msg = intres.getLocalizedMessage("ra.defaultadminprefsaved");            	
          getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED,msg);
       } catch (Exception e) {
           String msg = intres.getLocalizedMessage("ra.errorsavedefaultadminpref");            	
           getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED,msg);
           throw new EJBException(e);
       }
       if (log.isTraceEnabled()) {
    	   trace("<saveDefaultAdminPreference()");
       }
    } // saveDefaultAdminPreference

    /**
     * A method designed to be called at startuptime to (possibly) upgrade end entity profiles.
     * This method will read all End Entity Profiles and as a side-effect upgrade them if the version if changed for upgrade.
     * Can have a side-effect of upgrading a profile, therefore the Required transaction setting.
     * 
     * @param admin administrator calling the method
     * 
     * @ejb.transaction type="Required"
     * @ejb.interface-method
     */
    public void initializeAndUpgradeProfiles(Admin admin) {
    	try {
    		Collection result = profiledatahome.findAll();
    		Iterator iter = result.iterator();
    		while(iter.hasNext()){
    			EndEntityProfileDataLocal pdata = (EndEntityProfileDataLocal)iter.next();
    			String name = pdata.getProfileName();
    			pdata.upgradeProfile();
            	if (log.isDebugEnabled()) {
            		log.debug("Loaded end entity profile: "+name);
            	}
    		}
    	} catch (FinderException e) {
    		log.error("FinderException trying to load profiles: ", e);
    	}
    }
    
	/**
	  * Adds a profile to the database.
	  *
	  * @param admin administrator performing task
	  * @param profilename readable profile name
	  * @param profile profile to be added
     * @ejb.interface-method
	  *
	  */
	 public void addEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException {
		 addEndEntityProfile(admin,findFreeEndEntityProfileId(),profilename,profile);
	 } // addEndEntityProfile

	 /**
	  * Adds a profile to the database.
	  *
	  * @param admin administrator performing task
	  * @param profileid internal ID of new profile, use only if you know it's right.
	  * @param profilename readable profile name
	  * @param profile profile to be added
      * @ejb.interface-method
	  *
	  */
	 public void addEndEntityProfile(Admin admin, int profileid, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException{
		if(profilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)){
			String msg = intres.getLocalizedMessage("ra.erroraddprofile", profilename);            	
			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
			throw new EndEntityProfileExistsException();
		}
		if (isFreeEndEntityProfileId(profileid) == false) {
			String msg = intres.getLocalizedMessage("ra.erroraddprofile", profilename);            	
			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
			throw new EndEntityProfileExistsException();
		}
		try {
			profiledatahome.findByProfileName(profilename);
			String msg = intres.getLocalizedMessage("ra.erroraddprofile", profilename);            	
			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
			throw new EndEntityProfileExistsException();
		} catch (FinderException e) {
			try {
				profiledatahome.create(new Integer(profileid), profilename, profile);
				String msg = intres.getLocalizedMessage("ra.addedprofile", profilename);            	
				getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
						LogConstants.EVENT_INFO_ENDENTITYPROFILE,msg);
			} catch (Exception f) {
				String msg = intres.getLocalizedMessage("ra.erroraddprofile", profilename);            	
				error(msg, e);
				getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
						LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
			}
		 }
	 } // addEndEntityProfile

     /**
     * Adds a end entity profile to a group with the same content as the original profile.
      * @ejb.interface-method
     */
    public void cloneEndEntityProfile(Admin admin, String originalprofilename, String newprofilename) throws EndEntityProfileExistsException{
       EndEntityProfile profile = null;

       if(newprofilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)){
    	   String msg = intres.getLocalizedMessage("ra.errorcloneprofile", newprofilename, originalprofilename);            	
    	   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
    	   throw new EndEntityProfileExistsException();
       }
       try{
           EndEntityProfileDataLocal pdl = profiledatahome.findByProfileName(originalprofilename);
           profile = (EndEntityProfile) pdl.getProfile().clone();
           try{
             profiledatahome.findByProfileName(newprofilename);
      	   String msg = intres.getLocalizedMessage("ra.errorcloneprofile", newprofilename, originalprofilename);            	
             getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
             throw new EndEntityProfileExistsException();
           }catch(FinderException e){
              profiledatahome.create(new Integer(findFreeEndEntityProfileId()),newprofilename,profile);
  			String msg = intres.getLocalizedMessage("ra.clonedprofile", newprofilename, originalprofilename);            	
              getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_ENDENTITYPROFILE,msg);
           }
         }catch(Exception e){
      	   String msg = intres.getLocalizedMessage("ra.errorcloneprofile", newprofilename, originalprofilename);            	
      	   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA,  new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
         }

    } // cloneEndEntityProfile

     /**
     * Removes an end entity profile from the database.
     * @throws EJBException if a communication or other error occurs.
      * @ejb.interface-method
     */
    public void removeEndEntityProfile(Admin admin, String profilename) {
        try{
            EndEntityProfileDataLocal pdl = profiledatahome.findByProfileName(profilename);
            pdl.remove();
			String msg = intres.getLocalizedMessage("ra.removedprofile", profilename);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_ENDENTITYPROFILE,msg);
        }catch(Exception e){
			String msg = intres.getLocalizedMessage("ra.errorremoveprofile", profilename);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
        }
    } // removeEndEntityProfile

     /**
     * Renames a end entity profile
      * @ejb.interface-method
     */
    public void renameEndEntityProfile(Admin admin, String oldprofilename, String newprofilename) throws EndEntityProfileExistsException{
        if(newprofilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME) || oldprofilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)){
        	String msg = intres.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
            throw new EndEntityProfileExistsException();
        }
       try{
           profiledatahome.findByProfileName(newprofilename);
    	   String msg = intres.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);            	
           getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
           throw new EndEntityProfileExistsException();
       }catch(FinderException e){
           try{
               EndEntityProfileDataLocal pdl = profiledatahome.findByProfileName(oldprofilename);
               pdl.setProfileName(newprofilename);
               String msg = intres.getLocalizedMessage("ra.renamedprofile", oldprofilename, newprofilename);            	
               getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_ENDENTITYPROFILE,msg );
           }catch(FinderException f){
        	   String msg = intres.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);            	
        	   getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg );
           }
       }
    } // renameProfile

    /**
     * Updates profile data
     * @ejb.interface-method
     */
    public void changeEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile){
        try{
            EndEntityProfileDataLocal pdl = profiledatahome.findByProfileName(profilename);
            pdl.setProfile(profile);
			String msg = intres.getLocalizedMessage("ra.changedprofile", profilename);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_ENDENTITYPROFILE,msg);
        }catch(FinderException e){
			String msg = intres.getLocalizedMessage("ra.errorchangeprofile", profilename);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ENDENTITYPROFILE,msg);
        }
    }// changeEndEntityProfile

    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public Collection getAuthorizedEndEntityProfileIds(Admin admin){
      ArrayList returnval = new ArrayList();
      Collection result = null;

      HashSet authorizedcaids = new HashSet(getCAAdminSession().getAvailableCAs(admin));
      //debug("Admin authorized to "+authorizedcaids.size()+" CAs.");
      try{
          if(getAuthorizationSession().isAuthorizedNoLog(admin, "/super_administrator")) {
              returnval.add(new Integer(SecConst.EMPTY_ENDENTITYPROFILE));
          }
        }catch(AuthorizationDeniedException e){}

      try{
          result = profiledatahome.findAll();
          Iterator i = result.iterator();
          while(i.hasNext()){
              EndEntityProfileDataLocal next = (EndEntityProfileDataLocal) i.next();
              // Check if all profiles available CAs exists in authorizedcaids.
              String value = next.getProfile().getValue(EndEntityProfile.AVAILCAS, 0);
              //debug("AvailCAs: "+value);
              if (value != null) {
                  String[] availablecas = value.split(EndEntityProfile.SPLITCHAR);
                  //debug("No of available CAs: "+availablecas.length);
                  boolean allexists = true;
                  for(int j=0; j < availablecas.length; j++){
                      //debug("Available CA["+j+"]: "+availablecas[j]);
                      Integer caid = new Integer(availablecas[j]);
                      // If this is the special value ALLCAs we are authorized
                      if ( (caid.intValue() != SecConst.ALLCAS) && (!authorizedcaids.contains(caid)) ) {
                    	  allexists = false;
                    	  if (log.isDebugEnabled()) {
                    		  debug("Profile "+next.getId()+" not authorized");
                    	  }
                    	  break;
                      }
                  }
                  if(allexists) {
                      //debug("Adding "+next.getId());
                      returnval.add(next.getId());
                  }
              }
          }
      }catch(Exception e){
    	  String msg = intres.getLocalizedMessage("ra.errorgetids");    	  
          error(msg, e);
      }
      return returnval;
    } // getAuthorizedEndEntityProfileNames

    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name (String).
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public HashMap getEndEntityProfileIdToNameMap(Admin admin){
    	if (log.isTraceEnabled()) {
    		trace(">getEndEntityProfileIdToNameMap");
    	}
        HashMap returnval = new HashMap();
        Collection result = null;
        returnval.put(new Integer(SecConst.EMPTY_ENDENTITYPROFILE),EMPTY_ENDENTITYPROFILENAME);
        try{
            result = profiledatahome.findAll();
            //debug("Found "+result.size()+ " end entity profiles.");
            Iterator i = result.iterator();
            while(i.hasNext()){
                EndEntityProfileDataLocal next = (EndEntityProfileDataLocal) i.next();
                //debug("Added "+next.getId()+ ", "+next.getProfileName());
                returnval.put(next.getId(),next.getProfileName());
            }
        }catch(Exception e) {
        	String msg = intres.getLocalizedMessage("ra.errorreadprofiles");    	  
            error(msg, e);
        }
    	if (log.isTraceEnabled()) {
    		trace("<getEndEntityProfileIdToNameMap");
    	}
        return returnval;
      } // getEndEntityProfileIdToNameMap

     /**
     * Finds a end entity profile by id.
     * @ejb.transaction type="Supports"
      * @ejb.interface-method
     */
    public EndEntityProfile getEndEntityProfile(Admin admin, int id){
    	if (log.isTraceEnabled()) {
            log.trace(">getEndEntityProfile("+id+")");    		
    	}
        EndEntityProfile returnval=null;
        try{
            if(id==SecConst.EMPTY_ENDENTITYPROFILE) {
                returnval = new EndEntityProfile(true);
            }
            if(id!=0 && id != SecConst.EMPTY_ENDENTITYPROFILE) {
                returnval = (profiledatahome.findByPrimaryKey(Integer.valueOf(id))).getProfile();
            }
        }catch(FinderException e){
            // Ignore, but log, so we'll return null
    		log.debug("Did not find end entity profile with id: "+id);
        }
        if (log.isTraceEnabled()) {
            log.trace("<getEndEntityProfile(id): "+(returnval == null ? "null":"not null"));        	
        }
        return returnval;
    } // getEndEntityProfile

     /**
     * Finds a end entity profile by id.
     * @return null if profile isn't found
     * @ejb.transaction type="Supports"
      * @ejb.interface-method
     */
    public EndEntityProfile getEndEntityProfile(Admin admin, String profilename){
    	if (log.isTraceEnabled()) {
            log.trace(">getEndEntityProfile("+profilename+")");    		
    	}
        EndEntityProfile returnval=null;
        try{
          if(profilename.equals(EMPTY_ENDENTITYPROFILENAME)) {
              returnval = new EndEntityProfile(true);
          } else {
              returnval = (profiledatahome.findByProfileName(profilename)).getProfile();
          }
        }catch(FinderException e){
    		log.debug("Did not find end entity profile with name: "+profilename);
            // Ignore so we'll return null
        }
    	if (log.isTraceEnabled()) {
            log.trace("<getEndEntityProfile("+profilename+")");    		
    	}
        return returnval;
    } // getEndEntityProfile

     /**
     * Returns a end entity profiles id, given it's profilename
     *
     * @return the id or 0 if profile cannot be found.
     * @ejb.transaction type="Supports"
      * @ejb.interface-method
     */
    public int getEndEntityProfileId(Admin admin, String profilename){
    	if (log.isTraceEnabled()) {
    		log.trace(">getEndEntityProfileId("+profilename+")");    		
    	}
    	int returnval = 0;
    	if(profilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)) {
    		return SecConst.EMPTY_ENDENTITYPROFILE;
    	}
    	try{
    		Integer id = (profiledatahome.findByProfileName(profilename)).getId();
    		returnval = id.intValue();
    	}catch(FinderException e){
        	if (log.isDebugEnabled()) {
        		log.debug("Did not find end entity profile with name: "+profilename);
        	}
    		// Ignore so we'll return 0
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<getEndEntityProfileId("+profilename+")");    		
    	}
    	return returnval;
    } // getEndEntityProfileId

     /**
     * Returns a end entity profiles name given it's id.
     *
     * @return profilename or null if profile id doesn't exists.
     * @ejb.transaction type="Supports"
      * @ejb.interface-method
     */
    public String getEndEntityProfileName(Admin admin, int id){
      String returnval = null;
      if(id == SecConst.EMPTY_ENDENTITYPROFILE) {
        return EMPTY_ENDENTITYPROFILENAME;
      }
      try{
        returnval = (profiledatahome.findByPrimaryKey(Integer.valueOf(id))).getProfileName();
      }catch(FinderException e){
    	  if (log.isDebugEnabled()) {
    		  log.debug("Did not find end entity profile with id: "+id);
    	  }
      }

      return returnval;
    } // getEndEntityProfileName



     /**
     * Method to check if a certificateprofile exists in any of the end entity profiles. Used to avoid desyncronization of certificate profile data.
     *
     * @param certificateprofileid the certificatetype id to search for.
     * @return true if certificateprofile exists in any of the end entity profiles.
     * @ejb.transaction type="Supports"
      * @ejb.interface-method
     */
    public boolean existsCertificateProfileInEndEntityProfiles(Admin admin, int certificateprofileid){
      String[] availablecertprofiles=null;
      boolean exists = false;
      try{
        Collection result = profiledatahome.findAll();
        Iterator i = result.iterator();
        while(i.hasNext() && !exists){
          availablecertprofiles = ((EndEntityProfileDataLocal) i.next()).getProfile().getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
          for(int j=0; j < availablecertprofiles.length; j++){
            if(Integer.parseInt(availablecertprofiles[j]) == certificateprofileid){
              exists=true;
              break;
            }
          }
        }
      }catch(FinderException e){}

      return exists;
    }

     /**
     * Method to check if a CA exists in any of the end entity profiles. Used to avoid desyncronization of CA data.
     *
     * @param caid the caid to search for.
     * @return true if ca exists in any of the end entity profiles.
     * @ejb.transaction type="Supports"
      * @ejb.interface-method
     */
    public boolean existsCAInEndEntityProfiles(Admin admin, int caid){
      String[] availablecas=null;
      boolean exists = false;
      try{
        Collection result = profiledatahome.findAll();
        Iterator i = result.iterator();
        while(i.hasNext() && !exists){
        	EndEntityProfileDataLocal ep = (EndEntityProfileDataLocal) i.next();
          availablecas = ep.getProfile().getValue(EndEntityProfile.AVAILCAS, 0).split(EndEntityProfile.SPLITCHAR);
          for(int j=0; j < availablecas.length; j++){
            if(Integer.parseInt(availablecas[j]) == caid){
              exists=true;
              if (log.isDebugEnabled()) {
            	  debug("CA exists in entity profile "+ep.getProfileName());
              }
              break;
            }
          }
        }
      }catch(FinderException e){}

      return exists;
    } // existsCAProfileInEndEntityProfiles

         /**
     * Loads the global configuration from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method
     */
    public GlobalConfiguration loadGlobalConfiguration(Admin admin)  {
        try {
        	if (log.isTraceEnabled()) {
        		trace(">loadGlobalConfiguration()");
        	}
            // Only do the actual SQL query if we might update the configuration due to cache time anyhow
            if ( globalconfiguration!=null && lastupdatetime+MIN_TIME_BETWEEN_GLOBCONF_UPDATES > new Date().getTime() ){
                return globalconfiguration;
            }
            try{
                log.debug("Reading GlobalConfiguration");
                final GlobalConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey("0");
                if(gcdata!=null){
                    globalconfiguration = gcdata.getGlobalConfiguration();
                    lastupdatetime = new Date().getTime();
                }
            }catch (ObjectNotFoundException t) {
                log.debug("No default GlobalConfiguration exists. Trying to create a new one.");
                saveGlobalConfiguration(admin, new GlobalConfiguration());
                lastupdatetime = new Date().getTime();
            }catch (Throwable t) {
                log.error("Failed to load global configuration", t);
			}
            if ( globalconfiguration!=null ) {
                return globalconfiguration;
            }
            return new GlobalConfiguration();	// Fallback to create a new unsaved config
        } finally {
        	if (log.isTraceEnabled()) {
        		trace("<loadGlobalConfiguration()");
        	}
        }
    } //loadGlobalConfiguration

    /**
     * Saves the globalconfiguration
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method
     */

    public void saveGlobalConfiguration(Admin admin, GlobalConfiguration globalconfiguration)  {
    	if (log.isTraceEnabled()) {
    		trace(">saveGlobalConfiguration()");
    	}
    	String pk = "0";
    	try {
    		GlobalConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey(pk);
    		gcdata.setGlobalConfiguration(globalconfiguration);
			String msg = intres.getLocalizedMessage("ra.savedconf", gcdata.getConfigurationId());            	
    		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_EDITSYSTEMCONFIGURATION,msg);
    	}catch (javax.ejb.FinderException fe) {
    		// Global configuration doesn't yet exists.
    		try{
    			GlobalConfigurationDataLocal data1 = globalconfigurationhome.create(pk,globalconfiguration);
    			String msg = intres.getLocalizedMessage("ra.createdconf", data1.getConfigurationId());            	
    			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_EDITSYSTEMCONFIGURATION, msg);
    		} catch(CreateException e){
    			String msg = intres.getLocalizedMessage("ra.errorcreateconf");            	
    			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_EDITSYSTEMCONFIGURATION,msg);
    		}
    	}
    	this.globalconfiguration=globalconfiguration;
    	if (log.isTraceEnabled()) {
    		trace("<saveGlobalConfiguration()");
    	}
    } // saveGlobalConfiguration

    /**
     * @ejb.interface-method
     */
    public int findFreeEndEntityProfileId(){
      int id = getRandomInt();
      boolean foundfree = false;

      while(!foundfree){
        try{
          if(id > 1) {
        	  // will thwrow exception if this id is not found in the database
        	  profiledatahome.findByPrimaryKey(Integer.valueOf(id));
          }
          id++;
        }catch(FinderException e){
           foundfree = true;
        }
      }
      return id;
    } // findFreeEndEntityProfileId


    // Private methods

    private static Random random = null;
    /** Helper to re-use a Random object */
    private int getRandomInt() {
    	if (random == null) {
    		random = new Random(new Date().getTime());
    	}
    	return random.nextInt();
    }
    
	private boolean isFreeEndEntityProfileId(int id) {
			boolean foundfree = false;
			try {
				if (id > 1) {
					profiledatahome.findByPrimaryKey(Integer.valueOf(id));
				}
			} catch (FinderException e) {
				foundfree = true;
			}
			return foundfree;
		} // isFreeEndEntityProfileId

    /**
     * Changes the admin preference in the database. Returns false if admin preference doesn't exist.
     */
    private boolean updateAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference, boolean dolog){
    	if (log.isTraceEnabled()) {
    		log.trace(">updateAdminPreference(fingerprint : " + certificatefingerprint + ")");
    	}
       boolean ret = false;
        try {
        	AdminPreferencesDataLocal apdata1 = adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
        	apdata1.setAdminPreference(adminpreference);
        	// Earlier we used to remove and re-add the adminpreferences data
        	// I don't know why, but that did not work on Oracle AS, so lets just do what create does, and setAdminPreference.
        	/*
            adminpreferenceshome.remove(certificatefingerprint);
            try{
                AdminPreferencesDataLocal apdata2 = adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
                debug("Found admin preferences with id: "+apdata2.getId());
            }  catch (javax.ejb.FinderException fe) {
            	debug("Admin preferences has been removed: "+certificatefingerprint);
            }
            adminpreferenceshome.create(certificatefingerprint,adminpreference);
            try{
                AdminPreferencesDataLocal apdata3 = adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
                debug("Found admin preferences with id: "+apdata3.getId());
            }  catch (javax.ejb.FinderException fe) {
            	error("Admin preferences was not created: "+certificatefingerprint);
            }
            */
            if (dolog) {                
    			String msg = intres.getLocalizedMessage("ra.changedadminpref", certificatefingerprint);            	
                getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED,msg);
            }
            ret = true;
        } catch (javax.ejb.FinderException fe) {
             ret=false;
             if (dolog) {
            	 String msg = intres.getLocalizedMessage("ra.adminprefnotfound", certificatefingerprint);            	
                 getLogSession().log(admin,admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED,msg);
             }
        } catch(Exception e){
          throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<updateAdminPreference()");
    	}
        return ret;
    } // changeAdminPreference


} // LocalRaAdminSessionBean

