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
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.UserDataConstants;

/**
 * Authenticates users towards a user database.
 * @see OldAuthenticationSession
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AuthenticationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class OldAuthenticationSessionBean implements OldAuthenticationSessionLocal, OldAuthenticationSessionRemote {

    private static final Logger log = Logger.getLogger(OldAuthenticationSessionBean.class);
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private UserAdminSessionLocal userAdminSession;
    @EJB
    private LogSessionLocal logSession;
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @Override
    public EndEntityInformation authenticateUser(final AuthenticationToken admin, final String username, final String password)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
    	if (log.isTraceEnabled()) {
            log.trace(">authenticateUser(" + username + ", hiddenpwd)");
    	}
        try {
            // Find the user with username username, or throw FinderException
            final UserData data = UserData.findByUsername(entityManager, username);
            if (data == null) {
            	throw new ObjectNotFoundException("Could not find username " + username);
            }
            // Decrease the remaining login attempts. When zero, the status is set to STATUS_GENERATED
           	userAdminSession.decRemainingLoginAttempts(admin, username);
           	final int status = data.getStatus();
            if ( (status == UserDataConstants.STATUS_NEW) || (status == UserDataConstants.STATUS_FAILED) || (status == UserDataConstants.STATUS_INPROCESS) || (status == UserDataConstants.STATUS_KEYRECOVERY)) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to authenticate user: username="+username+", dn="+data.getSubjectDN()+", email="+data.getSubjectEmail()+", status="+status+", type="+data.getType());
            	}
                if (!data.comparePassword(password)) {
                	final String msg = intres.getLocalizedMessage("authentication.invalidpwd", username);            	
                	logSession.log(admin, data.getCaId(), LogConstants.MODULE_CA, new Date(),username, null, LogConstants.EVENT_ERROR_USERAUTHENTICATION,msg);
                	throw new AuthLoginException(msg);
                }
                // Resets the remaining login attempts as this was a successful login
                userAdminSession.resetRemainingLoginAttempts(admin, username);
            	// Log formal message that authentication was successful
                final String msg = intres.getLocalizedMessage("authentication.authok", username);            	
                logSession.log(admin, data.getCaId(), LogConstants.MODULE_CA, new Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION, msg);
            	if (log.isTraceEnabled()) {
                    log.trace("<authenticateUser("+username+", hiddenpwd)");
            	}
                return data.toUserDataVO();
            }
        	final String msg = intres.getLocalizedMessage("authentication.wrongstatus", UserDataConstants.getStatusText(status), Integer.valueOf(status), username);            	
        	logSession.log(admin, data.getCaId(), LogConstants.MODULE_CA, new Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION, msg);
            throw new AuthStatusException(msg);
        } catch (ObjectNotFoundException oe) {
        	final String msg = intres.getLocalizedMessage("authentication.usernotfound", username);            	
        	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(),username, null, LogConstants.EVENT_INFO_USERAUTHENTICATION, msg);
            throw oe;
        } catch (AuthStatusException se) {
            throw se;
        } catch (AuthLoginException le) {
            throw le;
        } catch (Exception e) {
            log.error(intres.getLocalizedMessage("error.unknown"), e);
            throw new EJBException(e);
        }
    }

    @Override
	public void finishUser(EndEntityInformation data) throws ObjectNotFoundException {
		if (log.isTraceEnabled()) {
			log.trace(">finishUser(" + data.getUsername() + ", hiddenpwd)");
		}
		// This admin can be the public web user, which may not be allowed to change status,
		// this is a bit ugly, but what can a man do...
		AuthenticationToken statusadmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("finishUser"));
		//Admin statusadmin = Admin.getInternalAdmin();
		try {
			
			// See if we are allowed for make more requests than this one. If not user status changed by decRequestCounter
			int counter = userAdminSession.decRequestCounter(statusadmin, data.getUsername());
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
