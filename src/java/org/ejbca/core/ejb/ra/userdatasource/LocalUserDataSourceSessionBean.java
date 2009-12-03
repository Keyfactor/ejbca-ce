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

package org.ejbca.core.ejb.ra.userdatasource;

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

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceConnectionException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;


/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @ejb.bean description="Session bean handling interface with user data sources"
 *   display-name="UserDataSourceSessionSB"
 *   name="UserDataSourceSession"
 *   jndi-name="UserDataSourceSession"
 *   local-jndi-name="UserDataSourceSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry name="DataSource"
 *   type="java.lang.String"
 *   value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 *
 * @ejb.ejb-external-ref description="The UserDataSource entity bean"
 *   view-type="local"
 *   ref-name="ejb/UserDataSourceDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ra.userdatasource.UserDataSourceDataLocalHome"
 *   business="org.ejbca.core.ejb.ra.userdatasource.UserDataSourceDataLocal"
 *   link="UserDataSourceData"
 *
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionRemote"
 *
 *  @jonas.bean ejb-name="UserDataSourceSession"
 */
public class LocalUserDataSourceSessionBean extends BaseSessionBean {

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /**
     * The local home interface of user data source entity bean.
     */
    private UserDataSourceDataLocalHome userdatasourcehome = null;

    /**
     * The local interface of authorization session bean
     */
    private IAuthorizationSessionLocal authorizationsession = null;

    private ICAAdminSessionLocal caAdminSession;

    /**
     * The remote interface of  log session bean
     */
    private ILogSessionLocal logsession = null;


    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
    	userdatasourcehome = (UserDataSourceDataLocalHome) getLocator().getLocalHome(UserDataSourceDataLocalHome.COMP_NAME);
    }


    /**
     * Gets connection to log session bean
     *
     * @return Connection
     */
    private ILogSessionLocal getLogSession() {
        if (logsession == null) {
            try {
                ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
                logsession = logsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return logsession;
    } //getLogSession


    /**
     * Gets connection to authorization session bean
     *
     * @return IAuthorizationSessionLocal
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if (authorizationsession == null) {
            try {
                IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) getLocator().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
                authorizationsession = authorizationsessionhome.create();
            } catch (CreateException e) {
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
     * Main method used to fetch userdata from the given user data sources
     * See BaseUserDataSource class for further documentation about function
     *
     * Checks that the administrator is authorized to fetch userdata.
     * 
     * @param userdatasourceids a Collection (Integer) of userdatasource Ids.
     * @return Collection of UserDataSourceVO, empty if no userdata could be found.
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
     */
    public Collection fetch(Admin admin, Collection userdatasourceids, String searchstring) throws AuthorizationDeniedException, UserDataSourceException{
        Iterator iter = userdatasourceids.iterator();
        ArrayList result = new ArrayList();
        while (iter.hasNext()) {
            Integer id = (Integer) iter.next();            
            try {            	
                UserDataSourceDataLocal pdl = userdatasourcehome.findByPrimaryKey(id);
                BaseUserDataSource userdatasource = pdl.getUserDataSource();
                if(isAuthorizedToUserDataSource(admin,id.intValue(),userdatasource,false)){
                  try {
                    result.addAll(pdl.getUserDataSource().fetchUserDataSourceVOs(admin,searchstring));
                    String msg = intres.getLocalizedMessage("userdatasource.fetcheduserdatasource", pdl.getName());            	
                    getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
                           null, LogConstants.EVENT_INFO_USERDATAFETCHED,msg);
                  } catch (UserDataSourceException pe) {
                      String msg = intres.getLocalizedMessage("userdatasource.errorfetchuserdatasource", pdl.getName());            	
                      getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
                              null, LogConstants.EVENT_ERROR_USERDATAFETCHED,msg);
                    throw pe;

                  }
                }else{
                	String msg = intres.getLocalizedMessage("userdatasource.errornotauth", pdl.getName());
                	getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
                }
            } catch (FinderException fe) {
                String msg = intres.getLocalizedMessage("userdatasource.erroruserdatasourceexist", id);            	
                getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_USERDATAFETCHED, msg);
                throw new UserDataSourceException(msg);

            }
        }

        return result;
    }


    /**
     * method used to remove userdata from the given user data sources.
     * This functionality is optianal of a user data implementation and
     * is not certain it is implemented
     * See BaseUserDataSource class for further documentation about function
     *
     * Checks that the administrator is authorized to remove userdata.
     * 
     * @param userdatasourceids a Collection (Integer) of userdatasource Ids.
     * @return true if the user was remove successfully from at least one of the user data sources.
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
     */
    public boolean removeUserData(Admin admin, Collection userdatasourceids, String searchstring, boolean removeMultipleMatch) throws AuthorizationDeniedException, MultipleMatchException, UserDataSourceException{
    	boolean retval = false;
        Iterator iter = userdatasourceids.iterator();
        while (iter.hasNext()) {
            Integer id = (Integer) iter.next();
            
            try {            	
                UserDataSourceDataLocal pdl = userdatasourcehome.findByPrimaryKey(id);
                BaseUserDataSource userdatasource = pdl.getUserDataSource();
                if(isAuthorizedToUserDataSource(admin,id.intValue(),userdatasource,true)){
                  try {
                    retval = retval || pdl.getUserDataSource().removeUserData(admin, searchstring, removeMultipleMatch);
                    String msg = intres.getLocalizedMessage("userdatasource.removeduserdata", pdl.getName());            	
                    getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
                           null, LogConstants.EVENT_INFO_USERDATAREMOVED,msg);
                  } catch (UserDataSourceException pe) {
                      String msg = intres.getLocalizedMessage("userdatasource.errorremovinguserdatasource", pdl.getName());            	
                      getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
                              null, LogConstants.EVENT_ERROR_USERDATAREMOVED,msg);
                    throw pe;

                  }
                }else{
                	String msg = intres.getLocalizedMessage("userdatasource.errornotauth", pdl.getName());
                	getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
                }
            } catch (FinderException fe) {
                String msg = intres.getLocalizedMessage("userdatasource.erroruserdatasourceexist", id);            	
                getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_USERDATAREMOVED, msg);
                throw new UserDataSourceException(msg);
            }
        }
        
        return retval;
    }
    
    

	/**
     * Test the connection to a user data source
     *
     * @param userdatasourceid the id of the userdatasource to test.
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
     */
    public void testConnection(Admin admin, int userdatasourceid) throws UserDataSourceConnectionException {
    	if (log.isTraceEnabled()) {
            log.trace(">testConnection(id: " + userdatasourceid + ")");
    	}
        try {
        	UserDataSourceDataLocal pdl = userdatasourcehome.findByPrimaryKey(new Integer(userdatasourceid));
        	BaseUserDataSource userdatasource = pdl.getUserDataSource();
        	if(isAuthorizedToEditUserDataSource(admin,userdatasource)){
        		try {
        			userdatasource.testConnection(admin);
        			String msg = intres.getLocalizedMessage("userdatasource.testedcon", pdl.getName());            	
        			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
        					null, LogConstants.EVENT_INFO_USERDATASOURCEDATA,msg);
        		} catch (UserDataSourceConnectionException pe) {
        			String msg = intres.getLocalizedMessage("userdatasource.errortestcon", pdl.getName());            	
        			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
        					LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg, pe);        			
        			throw pe;
        		}
        	}else{
    			String msg = intres.getLocalizedMessage("userdatasource.errortestconauth", pdl.getName());            	
            	getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
        	}
        } catch (FinderException fe) {
			String msg = intres.getLocalizedMessage("userdatasource.erroruserdatasourceexist", new Integer(userdatasourceid));            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg);
        }
    	if (log.isTraceEnabled()) {
            log.trace("<testConnection(id: " + userdatasourceid + ")");
    	}
    }

    /**
     * Adds a user data source to the database.
     *
     * @throws UserDataSourceExistsException if user data source already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void addUserDataSource(Admin admin, String name, BaseUserDataSource userdatasource) throws UserDataSourceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">addUserDataSource(name: " + name + ")");
    	}
        addUserDataSource(admin,findFreeUserDataSourceId().intValue(),name,userdatasource);
        log.trace("<addUserDataSource()");
    } // addUserDataSource


    /**
     * Adds a user data source to the database.
     * Used for importing and exporting profiles from xml-files.
     *
     * @throws UserDataSourceExistsException if user data source already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void addUserDataSource(Admin admin, int id, String name, BaseUserDataSource userdatasource) throws UserDataSourceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">addUserDataSource(name: " + name + ", id: " + id + ")");
    	}
        boolean success = false;
        if(isAuthorizedToEditUserDataSource(admin,userdatasource)){
        	try {
        		userdatasourcehome.findByName(name);
        	} catch (FinderException e) {
        		try {
        			userdatasourcehome.findByPrimaryKey(new Integer(id));
        		} catch (FinderException f) {
        			try {
        				userdatasourcehome.create(new Integer(id), name, userdatasource);
        				success = true;
        			} catch (CreateException g) {
        				error("Unexpected error creating new user data source: ", g);
        			}
        		}
        	}
        	if (success) {
    			String msg = intres.getLocalizedMessage("userdatasource.addedsource", name);            	
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
        	} else {
    			String msg = intres.getLocalizedMessage("userdatasource.erroraddsource", name);            	
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg);
        	}
        	if (!success) {
        		throw new UserDataSourceExistsException();
        	}
        }else{
			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", name);            	
        	getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
        }
        log.trace("<addUserDataSource()");
    } // addUserDataSource

    /**
     * Updates user data source data
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void changeUserDataSource(Admin admin, String name, BaseUserDataSource userdatasource) {
    	if (log.isTraceEnabled()) {
            log.trace(">changeUserDataSource(name: " + name + ")");
    	}
        boolean success = false;
        if(isAuthorizedToEditUserDataSource(admin,userdatasource)){
        	try {
        		UserDataSourceDataLocal htp = userdatasourcehome.findByName(name);
        		htp.setUserDataSource(userdatasource);
        		success = true;
        	} catch (FinderException e) {
        	}
        	
        	if (success) {
    			String msg = intres.getLocalizedMessage("userdatasource.changedsource", name);            	
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
        	} else {
    			String msg = intres.getLocalizedMessage("userdatasource.errorchangesource", name);            	
        		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg);
        	}
        }else{
			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", name);            	
        	getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
        }
        log.trace("<changeUserDataSource()");
    } // changeUserDataSource

    /**
     * Adds a user data source with the same content as the original.
     * @throws UserDataSourceExistsException 
     *
     * @throws UserDataSourceExistsException if user data source already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void cloneUserDataSource(Admin admin, String oldname, String newname) throws UserDataSourceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">cloneUserDataSource(name: " + oldname + ")");
    	}
        BaseUserDataSource userdatasourcedata = null;
        try {
        	UserDataSourceDataLocal htp = userdatasourcehome.findByName(oldname);
        	userdatasourcedata = (BaseUserDataSource) htp.getUserDataSource().clone();
        	if(isAuthorizedToEditUserDataSource(admin,userdatasourcedata)){                   		
        		try {
        			addUserDataSource(admin, newname, userdatasourcedata);
        			String msg = intres.getLocalizedMessage("userdatasource.clonedsource", newname, oldname);            	
        			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
        		} catch (UserDataSourceExistsException f) {
        			String msg = intres.getLocalizedMessage("userdatasource.errorclonesource", newname, oldname);            	
        			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg);
        			throw f;
        		}        		
        	}else{
    			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", oldname);            	
        		getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
        	}            
        } catch (FinderException e) {
			String msg = intres.getLocalizedMessage("userdatasource.errorclonesource", newname, oldname);            	
            error(msg, e);
            throw new EJBException(e);
        } catch (CloneNotSupportedException e) {
			String msg = intres.getLocalizedMessage("userdatasource.errorclonesource", newname, oldname);            	
            error(msg, e);
            throw new EJBException(e);
		}
        log.trace("<cloneUserDataSource()");
    } // cloneUserDataSource

    /**
     * Removes a user data source from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public boolean removeUserDataSource(Admin admin, String name) {
    	if (log.isTraceEnabled()) {
            log.trace(">removeUserDataSource(name: " + name + ")");
    	}
        boolean retval = false;
        try {
        	UserDataSourceDataLocal htp = userdatasourcehome.findByName(name);
        	BaseUserDataSource userdatasource = htp.getUserDataSource();
        	if(isAuthorizedToEditUserDataSource(admin,userdatasource)){        	
              htp.remove();
              String msg = intres.getLocalizedMessage("userdatasource.removedsource", name);            	
              getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
              retval = true;
        	}else{
    			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", name);            	
        		getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
        	}
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("userdatasource.errorremovesource", name);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg, e);
        }
        log.trace("<removeUserDataSource()");
        return retval;
    } // removeUserDataSource

    /**
     * Renames a user data source
     *
     * @throws UserDataSourceExistsException if user data source already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void renameUserDataSource(Admin admin, String oldname, String newname) throws UserDataSourceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">renameUserDataSource(from " + oldname + " to " + newname + ")");
    	}
        boolean success = false;
        try {
            userdatasourcehome.findByName(newname);
        } catch (FinderException e) {
            try {
            	UserDataSourceDataLocal htp = userdatasourcehome.findByName(oldname);
            	if(isAuthorizedToEditUserDataSource(admin,htp.getUserDataSource())){
                  htp.setName(newname);
                  success = true;
            	}else{
        			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", oldname);            	
            		getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
            	}
            } catch (FinderException g) {
            }
        }

        if (success) {
            String msg = intres.getLocalizedMessage("userdatasource.renamedsource", oldname, newname);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("userdatasource.errorrenamesource", oldname, newname);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg);
        }

        if (!success) {
            throw new UserDataSourceExistsException();
        }
        log.trace("<renameUserDataSource()");
    } // renameUserDataSource

    /**
     * Retrives a Collection of id:s (Integer) to authorized user data sources.
     *
     * @param indicates if sources with anyca set should be included
     * @return Collection of id:s (Integer)
     * @ejb.interface-method view-type="both"
     */
    public Collection getAuthorizedUserDataSourceIds(Admin admin, boolean includeAnyCA) {
        HashSet returnval = new HashSet();
        Collection result = null;
        boolean superadmin = false;
        // If superadmin return all available user data sources
        try {
        	try{
              superadmin = getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
        	}catch (AuthorizationDeniedException e1) {
              	log.debug("AuthorizationDeniedException: ", e1);
            }
            Collection authorizedcas = getCAAdminSession().getAvailableCAs(admin);
            result = this.userdatasourcehome.findAll();
            Iterator i = result.iterator();
            while (i.hasNext()) {
            	UserDataSourceDataLocal next = (UserDataSourceDataLocal) i.next();
            	if(superadmin){
                  returnval.add(next.getId());
            	}else{
            		BaseUserDataSource userdatasource = next.getUserDataSource();
            		if(userdatasource.getApplicableCAs().contains(new Integer(BaseUserDataSource.ANYCA))){
            			if(includeAnyCA){
            				returnval.add(next.getId());
            			}
            		}else{
            			if(authorizedcas.containsAll(userdatasource.getApplicableCAs())){
            				returnval.add(next.getId());
            			}
            		}
            	}
            }
        }  catch (FinderException fe) {
			String msg = intres.getLocalizedMessage("userdatasource.errorfindingall");            	
        	log.error(msg, fe);
        }

        return returnval;
    } // getAuthorizedUserDataSourceIds

    /**
     * Method creating a hashmap mapping user data source id (Integer) to user data source name (String).
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public HashMap getUserDataSourceIdToNameMap(Admin admin) {
        HashMap returnval = new HashMap();
        Collection result = null;

        try {
            result = userdatasourcehome.findAll();
            Iterator i = result.iterator();
            while (i.hasNext()) {
            	UserDataSourceDataLocal next = (UserDataSourceDataLocal) i.next();
                returnval.put(next.getId(), next.getName());
            }
        } catch (FinderException e) {
        }
        return returnval;
    } // getUserDataSourceIdToNameMap


    /**
     * Retrives a named user data source.
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public BaseUserDataSource getUserDataSource(Admin admin, String name) {
        BaseUserDataSource returnval = null;

        try {
        	BaseUserDataSource result = (userdatasourcehome.findByName(name)).getUserDataSource();
            if(isAuthorizedToEditUserDataSource(admin,result)){
            	returnval = result;
            }else{
    			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", name);            	
        		getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
            }
        } catch (FinderException e) {
            // return null if we cant find it
        }
        return returnval;
    } //  getUserDataSource

    /**
     * Finds a user data source by id.
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public BaseUserDataSource getUserDataSource(Admin admin, int id) {
        BaseUserDataSource returnval = null;

        try {            
        	BaseUserDataSource result = (userdatasourcehome.findByPrimaryKey(new Integer(id))).getUserDataSource();
            if(isAuthorizedToEditUserDataSource(admin,result)){
            	returnval = result;
            }else{
    			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", new Integer(id));            	
        		getLogSession().log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
            }
        } catch (FinderException e) {
            // return null if we cant find it
        }
        return returnval;
    } // getUserDataSource

    /**
     * Help method used by user data source proxys to indicate if it is time to
     * update it's data.
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */

    public int getUserDataSourceUpdateCount(Admin admin, int userdatasourceid) {
        int returnval = 0;

        try {
            returnval = (userdatasourcehome.findByPrimaryKey(new Integer(userdatasourceid))).getUpdateCounter();
        } catch (FinderException e) {
        }

        return returnval;
    }


    /**
     * Returns a user data source id, given it's user data source name
     *
     * @return the id or 0 if the user data source cannot be found.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public int getUserDataSourceId(Admin admin, String name) {
        int returnval = 0;

        try {
            Integer id = (userdatasourcehome.findByName(name)).getId();
            returnval = id.intValue();
        } catch (FinderException e) {
        }

        return returnval;
    } // getUserDataSourceId

    /**
     * Returns a user data source name given its id.
     *
     * @return the name or null if id doesnt exists
     * @throws EJBException if a communication or other error occurs.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public String getUserDataSourceName(Admin admin, int id) {
    	if (log.isTraceEnabled()) {
            log.trace(">getUserDataSourceName(id: " + id + ")");
    	}
        String returnval = null;
        UserDataSourceDataLocal htp = null;
        try {
            htp = userdatasourcehome.findByPrimaryKey(new Integer(id));
            if (htp != null) {
                returnval = htp.getName();
            }
        } catch (FinderException e) {
        }
        log.trace("<getUserDataSourceName()");
        return returnval;
    } // getUserDataSourceName
    
    /**
     * Method to check if an admin is authorized to fetch user data from userdata source
     * The following checks are performed.
     * 
     * 1. If the admin is an administrator
     * 2. If the admin is authorized to all cas applicable to userdata source.
     *    or
     *    If the userdatasource have "ANYCA" set.
     * 3. The admin is authorized to the fetch or remove rule depending on the remove parameter
     * @param if the call is aremove call, othervise fetch authorization is used.
     * @return true if the administrator is authorized
     */
    private boolean isAuthorizedToUserDataSource(Admin admin, int id,  BaseUserDataSource userdatasource,boolean remove) {    	
    		if(isAuthorizedNoLog(admin,AccessRulesConstants.ROLE_SUPERADMINISTRATOR)){
    			return true;
    		}
    		
    		if(remove){
    			isAuthorized(admin,AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_REMOVE_RIGHTS);
    		}else{
    			isAuthorized(admin,AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_FETCH_RIGHTS);    			
    		}
    		if(isAuthorizedNoLog(admin,AccessRulesConstants.ROLE_ADMINISTRATOR)){
    			if(userdatasource.getApplicableCAs().contains(new Integer(BaseUserDataSource.ANYCA))){
    				return true;
    			}
    			Collection authorizedcas = getCAAdminSession().getAvailableCAs(admin);
    			if(authorizedcas.containsAll(userdatasource.getApplicableCAs())){
    				return true;
    			}
    		}    	
    	
		return false;
	}
    
    
    private boolean isAuthorizedNoLog(Admin admin, String resource){
    	boolean retval = false;
    	try {
    		retval = getAuthorizationSession().isAuthorizedNoLog(admin, resource);
    	}catch (AuthorizationDeniedException e) {}
    	
    	return retval;
    }
    
    private boolean isAuthorized(Admin admin, String resource){
    	boolean retval = false;
    	try {
    		retval = getAuthorizationSession().isAuthorized(admin, resource);
    	}catch (AuthorizationDeniedException e) {}
    	
    	return retval;
    }
    
    /**
     * Method to check if an admin is authorized to edit an user data source
     * The following checks are performed.
     * 
     * 1. If the admin is an administrator
     * 2. If tha admin is authorized AccessRulesConstants.REGULAR_EDITUSERDATASOURCES
     * 3. Only the superadmin should have edit access to user data sources with 'ANYCA' set
     * 4. Administrators should be authorized to all the user data source applicable cas.
     * 
     * @return true if the administrator is authorized
     */
    private boolean isAuthorizedToEditUserDataSource(Admin admin, BaseUserDataSource userdatasource) {
    	try {
    		if(getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.ROLE_SUPERADMINISTRATOR)){
    			return true;
    		}
    	} catch (AuthorizationDeniedException e) {}
    	try {
    		if(getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.ROLE_ADMINISTRATOR) &&
    				getAuthorizationSession().isAuthorizedNoLog(admin,AccessRulesConstants.REGULAR_EDITUSERDATASOURCES)){
    			if(userdatasource.getApplicableCAs().contains(new Integer(BaseUserDataSource.ANYCA))){
    				return false;
    			}
    			Collection authorizedcas = getCAAdminSession().getAvailableCAs(admin);
    			if(authorizedcas.containsAll(userdatasource.getApplicableCAs())){
    				return true;
    			}
    		}
		} catch (AuthorizationDeniedException e) {}
    	
		return false;
	}


    private Integer findFreeUserDataSourceId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;

        while (!foundfree) {
            try {
                if (id > 1) {
                	// will throw exception if id is not found in the database
                	userdatasourcehome.findByPrimaryKey(new Integer(id));
                }
                id = ran.nextInt();
            } catch (FinderException e) {
                foundfree = true;
            }
        }
        return new Integer(id);
    } // findFreeUserDataSourceId


} // LocalUserDataSourceSessionBean
