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

package org.ejbca.core.model.authorization;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * A JavaBean handling the authorization in EJBCA.
 *
 * The main methods are isAthorized and authenticate.
 *
 * @version $Id$
 */
public class Authorizer implements Serializable {
   
    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(Authorizer.class);    

    private AccessTree accesstree;
    private int module;
    private LogSessionLocal logSession;
    private AuthorizationProxy authorizationProxy;

    /** Creates new EjbcaAthorization */
    public Authorizer(Collection<AdminGroup> admingroups, boolean cliEnabled, LogSessionLocal logsession, int module) {
        accesstree = new AccessTree();
        authorizationProxy = new AuthorizationProxy(accesstree, cliEnabled);
        buildAccessTree(admingroups);
        this.logSession = logsession;
        this.module=module;
    }
    
    /**
     * Method to check if a user is authorized to a resource
     *
     * @param admininformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @return true if authorized and false if not
     */
    public boolean isAuthorized(Admin admin, String resource) {
        if(admin == null) {
            if(log.isInfoEnabled()) {
                log.info("Administrator is null, and therefore group not authorized to resource : " + resource);
            }
            return false;
        }
        AdminInformation admininformation = admin.getAdminInformation();
        if(!authorizationProxy.isAuthorized(admininformation, resource)  && !authorizationProxy.isAuthorized(admininformation, "/super_administrator")){            
        	try {
        		if(!admininformation.isSpecialUser()) {
        			logSession.log(admin, admininformation.getX509Certificate(), module,   new java.util.Date(),null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Resource : " + resource);
        		} else {
        			logSession.log(admin, LogConstants.INTERNALCAID, module,   new java.util.Date(),null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Resource : " + resource);
        		}
        	} catch (Throwable e) {
        		log.info("Missed to log 'Admin not authorized to resource', admin="+admin.toString()+", resource="+resource, e);
        	}
            return false;
        }
        try {
            if(!admininformation.isSpecialUser()) {
                logSession.log(admin,admininformation.getX509Certificate(),  module, new java.util.Date(),null, null, LogConstants.EVENT_INFO_AUTHORIZEDTORESOURCE,"Resource : " + resource);       
            } else {
                logSession.log(admin, LogConstants.INTERNALCAID,  module, new java.util.Date(),null, null, LogConstants.EVENT_INFO_AUTHORIZEDTORESOURCE,"Resource : " + resource);
            }        	
        } catch (Throwable e) {
        	log.info("Missed to log 'Admin authorized to resource', admin="+admin.toString()+", resource="+resource, e);
        }
        return true;
    }
    
    
    /**
     * Method to check if a user is authorized to a resource without performing any logging
     *
     * @param AdminInformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @return true if authorized and false if not authorized
     */
    public boolean isAuthorizedNoLog(Admin admin, String resource) {
        if(admin == null) {
            if(log.isInfoEnabled()) {
                log.info("Administrator is null, and therefore group not authorized to resource : " + resource);
            }
            return false;
        }
        // Check in accesstree.

        return (authorizationProxy.isAuthorized(admin.getAdminInformation(), resource)  || authorizationProxy.isAuthorized(admin.getAdminInformation(), "/super_administrator"));
  
    }
    /**
     * Method to check if a group is authorized to a resource
     *
     * @param admininformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @return true if authorized
     */
    public boolean isGroupAuthorized(Admin admin, int pk, String resource) {
        if(admin == null) {
            if(log.isInfoEnabled()) {
                log.info("Administrator is null, and therefore group not authorized to resource : " + resource);
            }
            return false;
        }
        
        AdminInformation admininformation = admin.getAdminInformation();
        
        if(!authorizationProxy.isGroupAuthorized(admininformation.getGroupId(), resource)){
        	try {
        		if(!admininformation.isSpecialUser()) {
        			logSession.log(admin, admininformation.getX509Certificate(), module,   new java.util.Date(),null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);
        		} else {
        			logSession.log(admin, LogConstants.INTERNALCAID, module,   new java.util.Date(),null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);
        		}
        	} catch (Throwable e) {
        		log.info("Missed to log 'Admin group not authorized to resource', admin="+admin.toString()+", resource="+resource, e);
        	}
            return false;
        }
        try {
        	if(!admininformation.isSpecialUser()) {
        		logSession.log(admin,admininformation.getX509Certificate(),  module, new java.util.Date(),null, null, LogConstants.EVENT_INFO_AUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);       
        	} else {
        		logSession.log(admin, LogConstants.INTERNALCAID,  module, new java.util.Date(),null, null, LogConstants.EVENT_INFO_AUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);
        	}
        } catch (Throwable e) {
        	log.info("Missed to log 'Admin group authorized to resource', admin="+admin.toString()+", resource="+resource, e);
        }
        return true;
    }
    
    
    /**
     * Method to check if a group is authorized to a resource without performing any logging
     *
     * @param adminGroupId to groupId to check authorization for
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isGroupAuthorizedNoLog(int adminGroupId, String resource) {
        // Check in accesstree.
        return authorizationProxy.isGroupAuthorized(adminGroupId, resource);
    }
    
    /**
     * Method used to return an ArrayList of Integers indicating which CAids an administrator
     * is authorized to access.
     * @return Collection of Integer
     */
    public Collection<Integer> getAuthorizedCAIds(Admin admin, Collection<Integer> availableCaIds) {         
        ArrayList<Integer> returnval = new ArrayList<Integer>();  
        for(Integer caid : availableCaIds){
            if(isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid.toString())) {              
                returnval.add(caid); 
            }else {
            	if (log.isDebugEnabled()) {
            		log.debug("Admin not authorized to CA: "+caid);
            	}
            }
        }                         
        return returnval;
    }		   
    
    /**
     * Method used to return an Collection of Integers indicating which end entity profiles
     * the administrator is authorized to view.
     *
     * @param admin, the administrator 
     * @param rapriviledge should be one of the end entity profile authorization constants defined in AvailableAccessRules.
     * @param availableEndEntityProfileId a list of available EEP ids to test for authorization
     */ 
    public Collection<Integer> getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge, Collection<Integer> availableEndEntityProfileId){
        ArrayList<Integer> returnval = new ArrayList<Integer>();  
        Iterator<Integer> iter = availableEndEntityProfileId.iterator();
        while(iter.hasNext()){
            Integer profileid = iter.next();
            if(isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rapriviledge)) {     
                returnval.add(profileid); 
            } else {
            	if (log.isDebugEnabled()) {
            		log.debug("Admin not authorized to end entity profile: "+profileid);
            	}            	
            }
        }
        return returnval;
    }
    
    /** Metod to load the access data from database. */
    public void buildAccessTree(Collection<AdminGroup> admingroups){
        accesstree.buildTree(admingroups);
        authorizationProxy.clear();
    }
    
    /**
     * Throws an AuthorizationDeniedException. This method is merely a stop-gap
     * measure to make authorization handling a bit more elegant. This is merely
     * a temporary fix until we've found a better solution to authorization.
     * 
     * 
     * @param admin The Admin involved.
     * @param resource The resource to which admin was denied.
     * @param msg Any additional information. Can be null.
     * @throws AuthorizationDeniedException
     */
    public static void throwAuthorizationException(Admin admin, String resource, String msg) throws AuthorizationDeniedException {
        if(msg == null) {
            msg = "";
        }
        throw new AuthorizationDeniedException("Admin " + admin + " was not authorized to resource " + resource + ". " + msg);
    }
}
