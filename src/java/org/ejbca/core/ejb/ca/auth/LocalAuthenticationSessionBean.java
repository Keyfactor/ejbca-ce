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

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.ejb.ra.UserData;
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
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AuthenticationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class LocalAuthenticationSessionBean implements AuthenticationSessionLocal, AuthenticationSessionRemote {

    private static final Logger log = Logger.getLogger(LocalAuthenticationSessionBean.class);
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private UserAdminSessionLocal userSession;
    @EJB
    private LogSessionLocal logSession;
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
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
            // Find the user with username username, or throw FinderException
            UserData data = UserData.findByUsername(entityManager, username);
            if (data == null) {
            	throw new ObjectNotFoundException("Could not find username " + username);
            }
            // Decrease the remaining login attempts. When zero, the status is set to STATUS_GENERATED
           	userSession.decRemainingLoginAttempts(admin, data.getUsername());
			
           	int status = data.getStatus();
            if ( (status == UserDataConstants.STATUS_NEW) || (status == UserDataConstants.STATUS_FAILED) || (status == UserDataConstants.STATUS_INPROCESS) || (status == UserDataConstants.STATUS_KEYRECOVERY)) {
                log.debug("Trying to authenticate user: username="+data.getUsername()+", dn="+data.getSubjectDN()+", email="+data.getSubjectEmail()+", status="+data.getStatus()+", type="+data.getType());                
                
                UserDataVO ret = new UserDataVO(data.getUsername(), data.getSubjectDN(), data.getCaId(), data.getSubjectAltName(), data.getSubjectEmail(), 
                		data.getStatus(), data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId(),
                		new Date(data.getTimeCreated()), new Date(data.getTimeModified()), data.getTokenType(), data.getHardTokenIssuerId(), data.getExtendedInformation());  
                ret.setPassword(data.getClearPassword());   
                ret.setCardNumber(data.getCardNumber());
                
                if (data.comparePassword(password) == false)
                {
                	String msg = intres.getLocalizedMessage("authentication.invalidpwd", username);            	
                	logSession.log(admin, data.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_ERROR_USERAUTHENTICATION,msg);
                	throw new AuthLoginException(msg);
                }
                
                // Resets the remaining login attempts as this was a successful login
                userSession.resetRemainingLoginAttempts(admin, data.getUsername());
            	
                String msg = intres.getLocalizedMessage("authentication.authok", username);            	
                logSession.log(admin, data.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION,msg);
            	if (log.isTraceEnabled()) {
                    log.trace("<authenticateUser("+username+", hiddenpwd)");
            	}
                return ret;
            }
        	String msg = intres.getLocalizedMessage("authentication.wrongstatus", UserDataConstants.getStatusText(status), Integer.valueOf(status), username);            	
        	logSession.log(admin, data.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION,msg);
            throw new AuthStatusException(msg);
        } catch (ObjectNotFoundException oe) {
        	String msg = intres.getLocalizedMessage("authentication.usernotfound", username);            	
        	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION,msg);
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("error.unknown");            	
            log.error(msg, e);
            throw new EJBException(e);
        }
    }

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
        	UserDataVO data = userSession.findUser(admin, username);
        	if (data == null) {
        		throw new FinderException("User '"+username+"' can not be found.");
        	}
        	finishUser(data);
        } catch (FinderException e) {
            String msg = intres.getLocalizedMessage("authentication.usernotfound", username);               
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),username, null, LogConstants.EVENT_ERROR_USERAUTHENTICATION,msg);
            throw new ObjectNotFoundException(e.getMessage());
        } catch (AuthorizationDeniedException e) {
            // Should never happen
            log.error("AuthorizationDeniedException: ", e);
            throw new EJBException(e);
        }
		if (log.isTraceEnabled()) {
			log.trace("<finishUser("+username+", hiddenpwd)");
		}
    }

	/**
	 * Cleans the certificate serial number from the user data. Should be called after the data has been used.
	 * @param data
	 * @throws ObjectNotFoundException if the user does not exist.
	 * @ejb.interface-method
	 */
	public void cleanUserCertDataSN(UserDataVO data) throws ObjectNotFoundException {
		if (log.isTraceEnabled()) {
			log.trace(">cleanUserCertDataSN: " + data.getUsername());
		}
		// This admin can be the public web user, which may not be allowed to change status,
		// this is a bit ugly, but what can a man do...
		Admin statusadmin = new Admin(Admin.TYPE_INTERNALUSER);
		try {
			userSession.cleanUserCertDataSN(statusadmin, data.getUsername());
		} catch (FinderException e) {
			String msg = intres.getLocalizedMessage("authentication.usernotfound", data.getUsername());
			logSession.log(statusadmin, statusadmin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_INFO_USERAUTHENTICATION,msg);
			throw new ObjectNotFoundException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			// Should never happen
		    log.error("AuthorizationDeniedException: ", e);
			throw new EJBException(e);
		} catch (ApprovalException e) {
			// Should never happen
		    log.error("ApprovalException: ", e);
			throw new EJBException(e);
		} catch (WaitingForApprovalException e) {
			// Should never happen
		    log.error("ApprovalException: ", e);
			throw new EJBException(e);
		}
		if (log.isTraceEnabled()) {
			log.trace("<cleanUserCertDataSN: "+data.getUsername());
		}
	} 
	/**
	 * Set the status of a user to finished, called when a user has been successfully processed. If
	 * possible sets users status to UserData.STATUS_GENERATED, which means that the user cannot
	 * be authenticated anymore. NOTE: May not have any effect of user database is remote.
	 * User data may contain a counter with nr of requests before used should be set to generated. In this case
	 * this counter will be decreased, and if it reaches 0 status will be generated. 
	 *
	 * @param data
	 * @throws ObjectNotFoundException if the user does not exist.
	 * @ejb.interface-method
	 */
	public void finishUser(UserDataVO data) throws ObjectNotFoundException {
		if (log.isTraceEnabled()) {
			log.trace(">finishUser(" + data.getUsername() + ", hiddenpwd)");
		}
		// This admin can be the public web user, which may not be allowed to change status,
		// this is a bit ugly, but what can a man do...
		Admin statusadmin = new Admin(Admin.TYPE_INTERNALUSER);
		try {
			
			// See if we are allowed for make more requests than this one. If not user status changed by decRequestCounter
			int counter = userSession.decRequestCounter(statusadmin, data.getUsername());
			if (counter <= 0) {
				String msg = intres.getLocalizedMessage("authentication.statuschanged", data.getUsername());
				logSession.log(statusadmin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_INFO_CHANGEDENDENTITY,msg);
			} 
			if (log.isTraceEnabled()) {
				log.trace("<finishUser("+data.getUsername()+", hiddenpwd)");
			}
		} catch (FinderException e) {
			String msg = intres.getLocalizedMessage("authentication.usernotfound", data.getUsername());
			logSession.log(statusadmin, statusadmin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_ERROR_USERAUTHENTICATION,msg);
			throw new ObjectNotFoundException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			// Should never happen
			log.error("AuthorizationDeniedException: ", e);
			throw new EJBException(e);
		} catch (ApprovalException e) {
			// Should never happen
		    log.error("ApprovalException: ", e);
			throw new EJBException(e);
		} catch (WaitingForApprovalException e) {
			// Should never happen
		    log.error("ApprovalException: ", e);
			throw new EJBException(e);
		}
	}
}
