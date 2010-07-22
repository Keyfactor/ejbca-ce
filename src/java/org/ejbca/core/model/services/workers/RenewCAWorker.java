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
package org.ejbca.core.model.services.workers;

import java.security.cert.CertPathValidatorException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Worker renewing CA that is about to expire.
 * 
 * @author Tomas Gustavsson
 *
 * @version: $Id$
 */
public class RenewCAWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(RenewCAWorker.class);
    /** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();	
	
	private ICAAdminSessionLocal caadminsession = null;
	
	/** Flag is keys should be regenerated or not */
	public static final String PROP_RENEWKEYS           = "worker.renewkeys";
	
	/**
	 * Worker that makes a query to the Certificate Store about
	 * expiring certificates.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work() throws ServiceExecutionFailedException {
		log.trace(">Worker started");
		
		// Find CAs with expire date that is less than configured number of days 
		// ahead in the future		
		long millistoexpire = getTimeBeforeExpire();
		long now = new Date().getTime();
		long expiretime = now + millistoexpire;

		// Renew these CAs using the CAAdminSessionBean		
		// Check the "Generate new keys" checkbox so we can pass the correct parameter to CAAdminSessionBean
		Collection caids = getCAIdsToCheck(false);
		log.debug("Checking renewal for "+caids.size()+" CAs");
		Iterator iter = caids.iterator();
		while (iter.hasNext()) {
			Integer caid = (Integer)iter.next();
			CAInfo info = getCAAdminSession().getCAInfo(getAdmin(), caid.intValue());
			String caname = null;
			if (info != null) {
				caname = info.getName();
				Date expire = info.getExpireTime(); 
				log.debug("CA "+caname+" expires on "+expire);
				if (expire.before(new Date(expiretime))) {
					try {
						// Only try to renew active CAs
						// There should be other monitoring available to check if CAs that should not be off-line are off-line (HealthCheck)
						CATokenInfo tokeninfo = info.getCATokenInfo();
						log.debug("CA status is "+info.getStatus()+", CA token status is "+tokeninfo.getCATokenStatus());
						if ( (info.getStatus() == SecConst.CA_ACTIVE) && (tokeninfo.getCATokenStatus() == ICAToken.STATUS_ACTIVE) ) {
							getCAAdminSession().renewCA(getAdmin(), info.getCAId(), null, isRenewKeys());					
						} else {
							log.debug("Not trying to renew CA because CA and token status are not on-line.");
						}
					} catch (CADoesntExistsException e) {
						log.error("Error renewing CA: ", e);
					} catch (CATokenAuthenticationFailedException e) {
						log.error("Error renewing CA: ", e);
					} catch (CertPathValidatorException e) {
						log.error("Error renewing CA: ", e);
					} catch (CATokenOfflineException e) {
						log.error("Error renewing CA: ", e);
					} catch (AuthorizationDeniedException e) {
						log.error("Error renewing CA: ", e);
					}				
				}				
			} else {
				String msg = intres.getLocalizedMessage("services.errorworker.errornoca", caid, caname);
				log.error(msg);
			}
		}
		log.trace("<Worker ended");
	}
	
	protected boolean isRenewKeys() {
		return properties.getProperty(PROP_RENEWKEYS,"FALSE").equalsIgnoreCase("TRUE");
	}

	
	public ICAAdminSessionLocal getCAAdminSession(){
		if (caadminsession == null) {
			try {
				ICAAdminSessionLocalHome home = (ICAAdminSessionLocalHome) getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
				this.caadminsession = home.create();
			} catch (CreateException e) {
				log.error(e);
			}
		}
		return caadminsession;
	}

}
