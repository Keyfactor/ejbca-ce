/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.util.LinkedHashMap;
import java.util.Map;

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
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;

/**
 * Authenticates users towards a user database.
 * @see EndEntityAuthenticationSession
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EndEntityAuthenticationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EndEntityAuthenticationSessionBean implements EndEntityAuthenticationSessionLocal, EndEntityAuthenticationSessionRemote {

    private static final Logger log = Logger.getLogger(EndEntityAuthenticationSessionBean.class);
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    @Override
    public EndEntityInformation authenticateUser(final AuthenticationToken admin, final String username, final String password)
        throws ObjectNotFoundException, AuthStatusException, AuthLoginException {
    	if (log.isTraceEnabled()) {
            log.trace(">authenticateUser(" + username + ", hiddenpwd)");
    	}
        try {
            // Find the user with username username, or throw ObjectNotFoundException
            final UserData data = UserData.findByUsername(entityManager, username);
            if (data == null) {
            	throw new ObjectNotFoundException("Could not find username " + username);
            }
            // Decrease the remaining login attempts. When zero, the status is set to STATUS_GENERATED
           	endEntityManagementSession.decRemainingLoginAttempts(username);
           	final int status = data.getStatus();
            if ( (status == EndEntityConstants.STATUS_NEW) || (status == EndEntityConstants.STATUS_FAILED) || (status == EndEntityConstants.STATUS_INPROCESS) || (status == EndEntityConstants.STATUS_KEYRECOVERY)) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to authenticate user: username="+username+", dn="+data.getSubjectDN()+", email="+data.getSubjectEmail()+", status="+status+", type="+data.getType());
            	}
                if (!data.comparePassword(password)) {
                	final String msg = intres.getLocalizedMessage("authentication.invalidpwd", username);            	
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", msg);
                    auditSession.log(EjbcaEventTypes.CA_USERAUTH, EventStatus.FAILURE, ModuleTypes.CA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(data.getCaId()), null, username, details);
                	throw new AuthLoginException(ErrorCode.LOGIN_ERROR, msg);
                }
                // Resets the remaining login attempts as this was a successful login
                endEntityManagementSession.resetRemainingLoginAttempts(username);
            	// Log formal message that authentication was successful
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", intres.getLocalizedMessage("authentication.authok", username));
                auditSession.log(EjbcaEventTypes.CA_USERAUTH, EventStatus.SUCCESS, ModuleTypes.CA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(data.getCaId()), null, username, details);
            	if (log.isTraceEnabled()) {
                    log.trace("<authenticateUser("+username+", hiddenpwd)");
            	}
                return data.toEndEntityInformation();
            }
        	final String msg = intres.getLocalizedMessage("authentication.wrongstatus", EndEntityConstants.getStatusText(status), Integer.valueOf(status), username);
        	log.info(msg);
            throw new AuthStatusException(msg);
        } catch (ObjectNotFoundException oe) {
        	final String msg = intres.getLocalizedMessage("authentication.usernotfound", username);
        	log.info(msg);
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
	public void finishUser(final EndEntityInformation data) throws ObjectNotFoundException {
		if (log.isTraceEnabled()) {
			log.trace(">finishUser(" + data.getUsername() + ", hiddenpwd)");
		}
		try {
			
			// See if we are allowed for make more requests than this one. If not user status changed by decRequestCounter
			final int counter = endEntityManagementSession.decRequestCounter(data.getUsername());
			if (counter <= 0) {
				log.info(intres.getLocalizedMessage("authentication.statuschanged", data.getUsername()));
			} 
			if (log.isTraceEnabled()) {
				log.trace("<finishUser("+data.getUsername()+", hiddenpwd)");
			}
		} catch (FinderException e) {
			final String msg = intres.getLocalizedMessage("authentication.usernotfound", data.getUsername());
			log.info(msg);
			throw new ObjectNotFoundException(e.getMessage());
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
