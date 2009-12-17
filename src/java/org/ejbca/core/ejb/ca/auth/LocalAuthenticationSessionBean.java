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

package org.ejbca.core.ejb.ca.auth;

import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.UserDataLocal;
import org.ejbca.core.ejb.ra.UserDataLocalHome;
import org.ejbca.core.ejb.ra.UserDataPK;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;

/**
 * Authenticates users towards a user database.
 *
 * @version $Id$
 *
 * @ejb.bean
 *   display-name="AuthenticationSB"
 *   name="AuthenticationSession"
 *   jndi-name="AuthenticationSession"
 *   local-jndi-name="AuthenticationSessionLocal"
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
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ca.auth.IAuthenticationSessionRemote"
 *
 * @ejb.ejb-external-ref
 *   description="The User Admin session bean"
 *   view-type="local"
 *   ref-name="ejb/UserAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *   link="UserAdminSession"
 *   
 * @ejb.ejb-external-ref
 *   description="The User entity bean"
 *   view-type="local"
 *   ref-name="ejb/UserDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ra.UserDataLocalHome"
 *   business="org.ejbca.core.ejb.ra.UserDataLocal"
 *   link="UserData"
 *
 * @ejb.ejb-external-ref
 *   description="The Log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 */
public class LocalAuthenticationSessionBean extends BaseSessionBean {

    /** home interface to user entity bean */
    private UserDataLocalHome userHome = null;
    
    /** interface to user admin session bean */
    private IUserAdminSessionLocal usersession = null;
    
    /** The remote interface of the log session bean */
    private ILogSessionLocal logsession;
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     * @ejb.create-method
     */
    public void ejbCreate() throws CreateException {
        trace(">ejbCreate()");
        userHome = (UserDataLocalHome)getLocator().getLocalHome(UserDataLocalHome.COMP_NAME);
        trace("<ejbCreate()");
    }
    
    private ILogSessionLocal getLogSession() {
    	if (logsession == null) {
            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
            try {
   				logsession = logsessionhome.create();
			} catch (CreateException e) {
				throw new EJBException(e);
			}
    	}
    	return logsession;
    }
    
    private IUserAdminSessionLocal getUserSession() {
    	if (usersession == null) {
    		IUserAdminSessionLocalHome usersessionhome = (IUserAdminSessionLocalHome) getLocator().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
            try {
   				usersession = usersessionhome.create();
			} catch (CreateException e) {
				throw new EJBException(e);
			}
    	}
    	return usersession;
    }
    
    /**
     * Authenticates a user to the user database and returns the user DN.
     *
     * @param username unique username within the instance
     * @param password password for the user
     *
     * @return UserDataVO, never returns null
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @ejb.interface-method
     */
    public UserDataVO authenticateUser(Admin admin, String username, String password)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
    	if (log.isTraceEnabled()) {
            log.trace(">authenticateUser(" + username + ", hiddenpwd)");
    	}
        try {
            // Find the user with username username
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data = userHome.findByPrimaryKey(pk);
            
            // Decrease the remaining login attempts. When zero, the status is set to STATUS_GENERATED
           	getUserSession().decRemainingLoginAttempts(admin, data.getUsername());
			
           	int status = data.getStatus();
            if ( (status == UserDataConstants.STATUS_NEW) || (status == UserDataConstants.STATUS_FAILED) || (status == UserDataConstants.STATUS_INPROCESS) || (status == UserDataConstants.STATUS_KEYRECOVERY)) {
                debug("Trying to authenticate user: username="+data.getUsername()+", dn="+data.getSubjectDN()+", email="+data.getSubjectEmail()+", status="+data.getStatus()+", type="+data.getType());                
                
                UserDataVO ret = new UserDataVO(data.getUsername(), data.getSubjectDN(), data.getCaId(), data.getSubjectAltName(), data.getSubjectEmail(), 
                		data.getStatus(), data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId(),
                		new Date(data.getTimeCreated()), new Date(data.getTimeModified()), data.getTokenType(), data.getHardTokenIssuerId(), data.getExtendedInformation());  
                ret.setPassword(data.getClearPassword());   
                ret.setCardNumber(data.getCardNumber());
                
                if (data.comparePassword(password) == false)
                {
                	String msg = intres.getLocalizedMessage("authentication.invalidpwd", username);            	
                	getLogSession().log(admin, data.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_ERROR_USERAUTHENTICATION,msg);
                	throw new AuthLoginException(msg);
                }
                
                // Resets the remaining login attempts as this was a successful login
                getUserSession().resetRemainingLoginAttempts(admin, data.getUsername());
            	
                String msg = intres.getLocalizedMessage("authentication.authok", username);            	
                getLogSession().log(admin, data.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION,msg);
            	if (log.isTraceEnabled()) {
                    log.trace("<authenticateUser("+username+", hiddenpwd)");
            	}
                return ret;
            }
        	String msg = intres.getLocalizedMessage("authentication.wrongstatus", UserDataConstants.getStatusText(status), Integer.valueOf(status), username);            	
        	getLogSession().log(admin, data.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION,msg);
            throw new AuthStatusException(msg);
        } catch (ObjectNotFoundException oe) {
        	String msg = intres.getLocalizedMessage("authentication.usernotfound", username);            	
        	getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION,msg);
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("error.unknown");            	
            error(msg, e);
            throw new EJBException(e);
        }
    } //authenticateUser

    /**
     * Set the status of a user to finished, called when a user has been successfully processed. If
     * possible sets users status to UserData.STATUS_GENERATED, which means that the user cannot
     * be authenticated anymore. NOTE: May not have any effect of user database is remote.
     * User data may contain a counter with nr of requests before used should be set to generated. In this case
     * this counter will be decreased, and if it reaches 0 status will be generated. 
     *
     * @param username unique username within the instance
     * @param password password for the user
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @ejb.interface-method
     */
    public void finishUser(Admin admin, String username, String password) throws ObjectNotFoundException {
    	if (log.isTraceEnabled()) {
            log.trace(">finishUser(" + username + ", hiddenpwd)");
    	}
        try {
            // Change status of the user with username username
        	UserDataVO data = getUserSession().findUser(admin, username);
        	if (data == null) {
        		throw new FinderException("User '"+username+"' can not be found.");
        	}
        	// This admin can be the public web user, which may not be allowed to change status,
        	// this is a bit ugly, but what can a man do...
        	Admin statusadmin = new Admin(Admin.TYPE_INTERNALUSER);
        	
        	// See if we are allowed fo make more requests than this one
    		int counter = getUserSession().decRequestCounter(statusadmin, username);
    		if (counter <= 0) {
    			getUserSession().setUserStatus(statusadmin, username, UserDataConstants.STATUS_GENERATED);
    			String msg = intres.getLocalizedMessage("authentication.statuschanged", username);            	
    			getLogSession().log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY,msg);        		
    		} 
        	if (log.isTraceEnabled()) {
                log.trace("<finishUser("+username+", hiddenpwd)");
        	}
        } catch (FinderException e) {
        	String msg = intres.getLocalizedMessage("authentication.usernotfound", username);            	
        	getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_ERROR_USERAUTHENTICATION,msg);
            throw new ObjectNotFoundException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			// Should never happen
            error("AuthorizationDeniedException: ", e);
            throw new EJBException(e);
		} catch (ApprovalException e) {
			// Should never happen
            error("ApprovalException: ", e);
            throw new EJBException(e);
		} catch (WaitingForApprovalException e) {
			// Should never happen
            error("ApprovalException: ", e);
            throw new EJBException(e);
		}
    } //finishUser
}
