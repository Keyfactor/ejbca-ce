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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.ra.userdatasource.CustomUserDataSourceContainer;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceConnectionException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.util.Base64GetHashMap;

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
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "UserDataSourceSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class LocalUserDataSourceSessionBean implements UserDataSourceSessionLocal, UserDataSourceSessionRemote {

	private static final Logger log = Logger.getLogger(LocalUserDataSourceSessionBean.class);
	/** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private LogSessionLocal logSession;

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
    public Collection<UserDataSourceVO> fetch(Admin admin, Collection<Integer> userdatasourceids, String searchstring) throws AuthorizationDeniedException, UserDataSourceException{
    	Iterator<Integer> iter = userdatasourceids.iterator();
    	ArrayList<UserDataSourceVO> result = new ArrayList<UserDataSourceVO>();
    	while (iter.hasNext()) {
    		Integer id = iter.next();
    		UserDataSourceData pdl = UserDataSourceData.findById(entityManager, id);
    		if (pdl != null) {
    			BaseUserDataSource userdatasource = getUserDataSource(pdl);
    			if(isAuthorizedToUserDataSource(admin,id.intValue(),userdatasource,false)){
    				try {
    					result.addAll(getUserDataSource(pdl).fetchUserDataSourceVOs(admin,searchstring));
    					String msg = intres.getLocalizedMessage("userdatasource.fetcheduserdatasource", pdl.getName());            	
    					logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
    							null, LogConstants.EVENT_INFO_USERDATAFETCHED,msg);
    				} catch (UserDataSourceException pe) {
    					String msg = intres.getLocalizedMessage("userdatasource.errorfetchuserdatasource", pdl.getName());            	
    					logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
    							null, LogConstants.EVENT_ERROR_USERDATAFETCHED,msg);
    					throw pe;
    				}
    			}else{
    				String msg = intres.getLocalizedMessage("userdatasource.errornotauth", pdl.getName());
    				logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
    			}
    		} else {
    			String msg = intres.getLocalizedMessage("userdatasource.erroruserdatasourceexist", id);            	
    			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
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
    public boolean removeUserData(Admin admin, Collection<Integer> userdatasourceids, String searchstring, boolean removeMultipleMatch) throws AuthorizationDeniedException, MultipleMatchException, UserDataSourceException{
    	boolean retval = false;
    	Iterator<Integer> iter = userdatasourceids.iterator();
    	while (iter.hasNext()) {
    		Integer id = iter.next();
    		UserDataSourceData pdl = UserDataSourceData.findById(entityManager, id);
    		if (pdl != null) {
    			BaseUserDataSource userdatasource = getUserDataSource(pdl);
    			if(isAuthorizedToUserDataSource(admin,id.intValue(),userdatasource,true)){
    				try {
    					retval = retval || getUserDataSource(pdl).removeUserData(admin, searchstring, removeMultipleMatch);
    					String msg = intres.getLocalizedMessage("userdatasource.removeduserdata", pdl.getName());            	
    					logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
    							null, LogConstants.EVENT_INFO_USERDATAREMOVED,msg);
    				} catch (UserDataSourceException pe) {
    					String msg = intres.getLocalizedMessage("userdatasource.errorremovinguserdatasource", pdl.getName());            	
    					logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
    							null, LogConstants.EVENT_ERROR_USERDATAREMOVED,msg);
    					throw pe;

    				}
    			}else{
    				String msg = intres.getLocalizedMessage("userdatasource.errornotauth", pdl.getName());
    				logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
    			}
    		} else {
    			String msg = intres.getLocalizedMessage("userdatasource.erroruserdatasourceexist", id);            	
    			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
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
    	UserDataSourceData pdl = UserDataSourceData.findById(entityManager, userdatasourceid);
    	if (pdl != null) {
        	BaseUserDataSource userdatasource = getUserDataSource(pdl);
        	if(isAuthorizedToEditUserDataSource(admin,userdatasource)){
        		try {
        			userdatasource.testConnection(admin);
        			String msg = intres.getLocalizedMessage("userdatasource.testedcon", pdl.getName());            	
        			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null,
        					null, LogConstants.EVENT_INFO_USERDATASOURCEDATA,msg);
        		} catch (UserDataSourceConnectionException pe) {
        			String msg = intres.getLocalizedMessage("userdatasource.errortestcon", pdl.getName());            	
        			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
        					LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg, pe);        			
        			throw pe;
        		}
        	}else{
    			String msg = intres.getLocalizedMessage("userdatasource.errortestconauth", pdl.getName());            	
            	logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
        	}
    	} else {
			String msg = intres.getLocalizedMessage("userdatasource.erroruserdatasourceexist", new Integer(userdatasourceid));            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
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
    }

    /**
     * Adds a user data source to the database.
     * Used for importing and exporting profiles from xml-files.
     *
     * @throws UserDataSourceExistsException if user data source already exists.
     * @ejb.interface-method view-type="both"
     */
    public void addUserDataSource(Admin admin, int id, String name, BaseUserDataSource userdatasource) throws UserDataSourceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">addUserDataSource(name: " + name + ", id: " + id + ")");
    	}
        boolean success = false;
        if (isAuthorizedToEditUserDataSource(admin,userdatasource)) {
        	if (UserDataSourceData.findByName(entityManager, name) == null) {
        		if (UserDataSourceData.findById(entityManager, id) == null) {
        			try {
        				entityManager.persist(new UserDataSourceData(new Integer(id), name, userdatasource));
        				success = true;
        			} catch (Exception e) {
        				log.error("Unexpected error creating new user data source: ", e);
        			}
        		}
        	}
        	if (success) {
    			String msg = intres.getLocalizedMessage("userdatasource.addedsource", name);            	
        		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
        	} else {
    			String msg = intres.getLocalizedMessage("userdatasource.erroraddsource", name);            	
        		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg);
        		throw new UserDataSourceExistsException();
        	}
        } else {
			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", name);            	
        	logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
        }
        log.trace("<addUserDataSource()");
    }

    /**
     * Updates user data source data
     *
     * @ejb.interface-method view-type="both"
     */
    public void changeUserDataSource(Admin admin, String name, BaseUserDataSource userdatasource) {
    	if (log.isTraceEnabled()) {
            log.trace(">changeUserDataSource(name: " + name + ")");
    	}
        boolean success = false;
        if(isAuthorizedToEditUserDataSource(admin,userdatasource)){
        	UserDataSourceData htp = UserDataSourceData.findByName(entityManager, name);
        	if (htp != null) {
        		htp.setUserDataSource(userdatasource);
        		success = true;
        	}
        	if (success) {
    			String msg = intres.getLocalizedMessage("userdatasource.changedsource", name);            	
        		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
        	} else {
    			String msg = intres.getLocalizedMessage("userdatasource.errorchangesource", name);            	
        		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg);
        	}
        }else{
			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", name);            	
        	logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
        }
        log.trace("<changeUserDataSource()");
    }

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
        UserDataSourceData htp = UserDataSourceData.findByName(entityManager, oldname);
        if (htp == null) {
			String msg = intres.getLocalizedMessage("userdatasource.errorclonesource", newname, oldname);            	
            log.error(msg);
            throw new EJBException(msg);
        }
        try {
        	userdatasourcedata = (BaseUserDataSource) getUserDataSource(htp).clone();
        	if(isAuthorizedToEditUserDataSource(admin,userdatasourcedata)){                   		
        		try {
        			addUserDataSource(admin, newname, userdatasourcedata);
        			String msg = intres.getLocalizedMessage("userdatasource.clonedsource", newname, oldname);            	
        			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
        		} catch (UserDataSourceExistsException f) {
        			String msg = intres.getLocalizedMessage("userdatasource.errorclonesource", newname, oldname);            	
        			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg);
        			throw f;
        		}        		
        	}else{
    			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", oldname);            	
        		logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
        	}            
        } catch (CloneNotSupportedException e) {
			String msg = intres.getLocalizedMessage("userdatasource.errorclonesource", newname, oldname);            	
            log.error(msg, e);
            throw new EJBException(e);
		}
        log.trace("<cloneUserDataSource()");
    }

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
    	UserDataSourceData htp = UserDataSourceData.findByName(entityManager, name);
    	try {
    		if (htp == null) {
    			throw new Exception("No such UserDataSource.");
    		}
    		BaseUserDataSource userdatasource = getUserDataSource(htp);
    		if(isAuthorizedToEditUserDataSource(admin,userdatasource)){
    			entityManager.remove(htp);
    			String msg = intres.getLocalizedMessage("userdatasource.removedsource", name);            	
    			logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
    			retval = true;
    		}else{
    			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", name);            	
    			logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
    		}
    	} catch (Exception e) {
    		String msg = intres.getLocalizedMessage("userdatasource.errorremovesource", name);            	
    		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg, e);
    	}
    	log.trace("<removeUserDataSource()");
    	return retval;
    }

    /**
     * Renames a user data source
     *
     * @throws UserDataSourceExistsException if user data source already exists.
     * @ejb.interface-method view-type="both"
     */
    public void renameUserDataSource(Admin admin, String oldname, String newname) throws UserDataSourceExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">renameUserDataSource(from " + oldname + " to " + newname + ")");
    	}
        boolean success = false;
        if (UserDataSourceData.findByName(entityManager, newname) == null) {
        	UserDataSourceData htp = UserDataSourceData.findByName(entityManager, oldname);
        	if (htp != null) {
            	if(isAuthorizedToEditUserDataSource(admin,getUserDataSource(htp))){
                  htp.setName(newname);
                  success = true;
            	}else{
        			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", oldname);            	
            		logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE, msg);
            	}
            }
        }
        if (success) {
        	String msg = intres.getLocalizedMessage("userdatasource.renamedsource", oldname, newname);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_USERDATASOURCEDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("userdatasource.errorrenamesource", oldname, newname);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_USERDATASOURCEDATA, msg);
            throw new UserDataSourceExistsException();
        }
        log.trace("<renameUserDataSource()");
    }

    /**
     * Retrieves a Collection of id:s (Integer) to authorized user data sources.
     *
     * @param indicates if sources with anyca set should be included
     * @return Collection of id:s (Integer)
     * @ejb.interface-method view-type="both"
     */
    public Collection<Integer> getAuthorizedUserDataSourceIds(Admin admin, boolean includeAnyCA) {
        HashSet<Integer> returnval = new HashSet<Integer>();
        boolean superadmin = false;
        // If superadmin return all available user data sources
        try{
        	superadmin = authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
        }catch (AuthorizationDeniedException e1) {
        	log.debug("AuthorizationDeniedException: ", e1);
        }
        Collection<Integer> authorizedcas = caAdminSession.getAvailableCAs(admin);
        Iterator<UserDataSourceData> i = UserDataSourceData.findAll(entityManager).iterator();
        while (i.hasNext()) {
        	UserDataSourceData next = i.next();
        	if(superadmin){
        		returnval.add(next.getId());
        	}else{
        		BaseUserDataSource userdatasource = getUserDataSource(next);
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
        return returnval;
    }

    /**
     * Method creating a hashmap mapping user data source id (Integer) to user data source name (String).
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public HashMap<Integer,String> getUserDataSourceIdToNameMap(Admin admin) {
        HashMap<Integer,String> returnval = new HashMap<Integer,String>();
        Collection<UserDataSourceData> result = UserDataSourceData.findAll(entityManager);
        Iterator<UserDataSourceData> i = result.iterator();
        while (i.hasNext()) {
        	UserDataSourceData next = i.next();
        	returnval.put(next.getId(), next.getName());
        }
        return returnval;
    }

    /**
     * Retrieves a named user data source.
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public BaseUserDataSource getUserDataSource(Admin admin, String name) {
        BaseUserDataSource returnval = null;
        UserDataSourceData udsd = UserDataSourceData.findByName(entityManager, name);
        if (udsd != null) {
        	BaseUserDataSource result = getUserDataSource(udsd);
            if(isAuthorizedToEditUserDataSource(admin,result)){
            	returnval = result;
            }else{
    			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", name);            	
        		logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
            }
        }
        return returnval;
    }

    /**
     * Finds a user data source by id.
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public BaseUserDataSource getUserDataSource(Admin admin, int id) {
        BaseUserDataSource returnval = null;
        UserDataSourceData udsd = UserDataSourceData.findById(entityManager, id);
        if (udsd != null) {
        	BaseUserDataSource result = getUserDataSource(udsd);
            if(isAuthorizedToEditUserDataSource(admin,result)){
            	returnval = result;
            }else{
    			String msg = intres.getLocalizedMessage("userdatasource.errornotauth", new Integer(id));            	
        		logSession.log(admin, admin.getCaId(),LogConstants.MODULE_RA,new Date(),null,null,LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,msg);
            }
        }
        return returnval;
    }

    /**
     * Help method used by user data source proxys to indicate if it is time to
     * update it's data.
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public int getUserDataSourceUpdateCount(Admin admin, int userdatasourceid) {
        int returnval = 0;
        UserDataSourceData udsd = UserDataSourceData.findById(entityManager, userdatasourceid);
        if (udsd != null) {
        	returnval = udsd.getUpdateCounter();
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
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public int getUserDataSourceId(Admin admin, String name) {
        int returnval = 0;
        UserDataSourceData udsd = UserDataSourceData.findByName(entityManager, name);
        if (udsd != null) {
        	returnval = udsd.getId();
        }
        return returnval;
    }

    /**
     * Returns a user data source name given its id.
     *
     * @return the name or null if id doesnt exists
     * @throws EJBException if a communication or other error occurs.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public String getUserDataSourceName(Admin admin, int id) {
    	if (log.isTraceEnabled()) {
            log.trace(">getUserDataSourceName(id: " + id + ")");
    	}
        String returnval = null;
        UserDataSourceData udsd = UserDataSourceData.findById(entityManager, id);
        if (udsd != null) {
        	returnval = udsd.getName();
        }
        log.trace("<getUserDataSourceName()");
        return returnval;
    }
    
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
    		Collection<Integer> authorizedcas = caAdminSession.getAvailableCAs(admin);
    		if(authorizedcas.containsAll(userdatasource.getApplicableCAs())){
    			return true;
    		}
    	}    	
		return false;
	}

    private boolean isAuthorizedNoLog(Admin admin, String resource){
    	boolean retval = false;
    	try {
    		retval = authorizationSession.isAuthorizedNoLog(admin, resource);
    	} catch (AuthorizationDeniedException e) {
    	}
    	return retval;
    }
    
    private boolean isAuthorized(Admin admin, String resource){
    	boolean retval = false;
    	try {
    		retval = authorizationSession.isAuthorized(admin, resource);
    	} catch (AuthorizationDeniedException e) {
    	}
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
    		if(authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.ROLE_SUPERADMINISTRATOR)){
    			return true;
    		}
    	} catch (AuthorizationDeniedException e) {
    	}
    	try {
    		if(authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.ROLE_ADMINISTRATOR) &&
    				authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.REGULAR_EDITUSERDATASOURCES)){
    			if(userdatasource.getApplicableCAs().contains(new Integer(BaseUserDataSource.ANYCA))){
    				return false;
    			}
    			Collection<Integer> authorizedcas = caAdminSession.getAvailableCAs(admin);
    			if(authorizedcas.containsAll(userdatasource.getApplicableCAs())){
    				return true;
    			}
    		}
		} catch (AuthorizationDeniedException e) {
		}
		return false;
	}

    private Integer findFreeUserDataSourceId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;
        while (!foundfree) {
        	if (id > 1) {
        		if (UserDataSourceData.findById(entityManager, id) == null) {
        			foundfree = true;
        		}
        	}
        	id = ran.nextInt();
        }
        return new Integer(id);
    }

    /**
     * Method that returns the userdatasource data and updates it if necessary.
     */
    private BaseUserDataSource getUserDataSource(UserDataSourceData udsData) {
    	BaseUserDataSource userdatasource = udsData.getCachedUserDataSource();
        if (userdatasource == null) {
        	java.beans.XMLDecoder decoder;
        	try {
        		decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(udsData.getData().getBytes("UTF8")));
        	} catch (UnsupportedEncodingException e) {
        		throw new EJBException(e);
        	}
        	HashMap h = (HashMap) decoder.readObject();
        	decoder.close();
        	// Handle Base64 encoded string values
        	HashMap data = new Base64GetHashMap(h);
        	switch (((Integer) (data.get(BaseUserDataSource.TYPE))).intValue()) {
        	case CustomUserDataSourceContainer.TYPE_CUSTOMUSERDATASOURCECONTAINER:
        		userdatasource = new CustomUserDataSourceContainer();
        		break;
        	}
        	userdatasource.loadData(data);
    	}
    	return userdatasource;
    }
}
