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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.authorization.AdminGroupDataLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * A JavaBean handling the authorization in EJBCA.
 *
 * The main methods are isAthorized and authenticate.
 *
 * @version $Id$
 */
public class Authorizer extends Object implements java.io.Serializable {
    
    private static final Logger log = Logger.getLogger(Authorizer.class);    

    // Private fields.
    private AccessTree            accesstree;
    private int                   module;
    
    private ILogSessionLocal               logsession;
    private AuthorizationProxy             authorizationproxy;

    /** Creates new EjbcaAthorization */
    public Authorizer(Collection admingroups, ILogSessionLocal logsession, int module) {
        accesstree = new AccessTree();
        authorizationproxy = new AuthorizationProxy(accesstree);
        buildAccessTree(admingroups);
        this.logsession = logsession;
        this.module=module;
    }
    
    // Public methods.
    
    /**
     * Method to check if a user is authorized to a resource
     *
     * @param admininformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorized(Admin admin, String resource) throws AuthorizationDeniedException {
        
        if(admin == null) {
            throw  new AuthorizationDeniedException("Administrator is null, and therefore not authorized to resource : " + resource);
        }
        
        AdminInformation admininformation = admin.getAdminInformation();
        
        if(!authorizationproxy.isAuthorized(admininformation, resource)  && !authorizationproxy.isAuthorized(admininformation, "/super_administrator")){
        	try {
        		if(!admininformation.isSpecialUser()) {
        			logsession.log(admin, admininformation.getX509Certificate(), module,   new java.util.Date(),null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Resource : " + resource);
        		} else {
        			logsession.log(admin, LogConstants.INTERNALCAID, module,   new java.util.Date(),null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Resource : " + resource);
        		}
        	} catch (Throwable e) {
        		log.info("Missed to log 'Admin not authorized to resource', admin="+admin.toString()+", resource="+resource, e);
        	}
            throw  new AuthorizationDeniedException("Administrator not authorized to resource : " + resource);
        }
        try {
            if(!admininformation.isSpecialUser()) {
                logsession.log(admin,admininformation.getX509Certificate(),  module, new java.util.Date(),null, null, LogConstants.EVENT_INFO_AUTHORIZEDTORESOURCE,"Resource : " + resource);       
            } else {
                logsession.log(admin, LogConstants.INTERNALCAID,  module, new java.util.Date(),null, null, LogConstants.EVENT_INFO_AUTHORIZEDTORESOURCE,"Resource : " + resource);
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
     * @return true if authorized
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isAuthorizedNoLog(Admin admin, String resource) throws AuthorizationDeniedException {
        if(admin == null) {
            throw  new AuthorizationDeniedException("Administrator is null, and therefore not authorized to resource : " + resource);
        }
        
        // Check in accesstree.
        if(!authorizationproxy.isAuthorized(admin.getAdminInformation(), resource)  && !authorizationproxy.isAuthorized(admin.getAdminInformation(), "/super_administrator")){
            throw  new AuthorizationDeniedException("Administrator not authorized to resource : " + resource);
        }
        return true;
    }
    
    /**
     * Method to check if a group is authorized to a resource
     *
     * @param admininformation information about the user to be authorized.
     * @param resource the resource to look up.
     * @return true if authorizes
     * @throws AuthorizationDeniedException when authorization is denied.
     */
    public boolean isGroupAuthorized(Admin admin, int pk, String resource) throws AuthorizationDeniedException {
        if(admin == null) {
            throw  new AuthorizationDeniedException("Administrator is null, and therefore group not authorized to resource : " + resource);
        }
        
        AdminInformation admininformation = admin.getAdminInformation();
        
        if(!authorizationproxy.isGroupAuthorized(admininformation.getGroupId(), resource)){
        	try {
        		if(!admininformation.isSpecialUser()) {
        			logsession.log(admin, admininformation.getX509Certificate(), module,   new java.util.Date(),null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);
        		} else {
        			logsession.log(admin, LogConstants.INTERNALCAID, module,   new java.util.Date(),null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);
        		}
        	} catch (Throwable e) {
        		log.info("Missed to log 'Admin group not authorized to resource', admin="+admin.toString()+", resource="+resource, e);
        	}
            throw  new AuthorizationDeniedException("Administrator group not authorized to resource : " + resource);
        }
        try {
        	if(!admininformation.isSpecialUser()) {
        		logsession.log(admin,admininformation.getX509Certificate(),  module, new java.util.Date(),null, null, LogConstants.EVENT_INFO_AUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);       
        	} else {
        		logsession.log(admin, LogConstants.INTERNALCAID,  module, new java.util.Date(),null, null, LogConstants.EVENT_INFO_AUTHORIZEDTORESOURCE,"Adminstrator group not authorized to resource : " + resource);
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
    public boolean isGroupAuthorizedNoLog(int adminGroupId, String resource) throws AuthorizationDeniedException {
        // Check in accesstree.
        if(!authorizationproxy.isGroupAuthorized(adminGroupId, resource)) {
            throw  new AuthorizationDeniedException("Administrator group not authorized to resource : " + resource);
        }
        return true;
    }
    
    /**
     * Method used to return an ArrayList of Integers indicating which CAids an administrator
     * is authorized to access.
     * @return Collection of Integer
     */
    public Collection getAuthorizedCAIds(Admin admin, Collection availableCaIds) {         
        ArrayList returnval = new ArrayList();  
        Iterator iter = availableCaIds.iterator();
        
        while(iter.hasNext()){
            Integer caid = (Integer) iter.next();
            try{           
                isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid.toString());               
                returnval.add(caid); 
            }catch(AuthorizationDeniedException e){
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
    public Collection getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge, Collection availableEndEntityProfileId){
        ArrayList returnval = new ArrayList();  
        Iterator iter = availableEndEntityProfileId.iterator();
        
        while(iter.hasNext()){
            Integer profileid = (Integer) iter.next();
            try{
                isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rapriviledge);     
                returnval.add(profileid); 
            }catch(AuthorizationDeniedException e){
            	if (log.isDebugEnabled()) {
            		log.debug("Admin not authorized to end entity profile: "+profileid);
            	}            	
            }
            
        }
        
        return returnval;
    }
    
    /** Metod to load the access data from database. */
    public void buildAccessTree(Collection admingroups){
        accesstree.buildTree(admingroups);
        authorizationproxy.clear();
    }
    
    
}
