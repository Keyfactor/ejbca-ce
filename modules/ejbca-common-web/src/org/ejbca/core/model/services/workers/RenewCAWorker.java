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
package org.ejbca.core.model.services.workers;

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExecutionResult;
import org.ejbca.core.model.services.ServiceExecutionResult.Result;

/**
 * Worker renewing CA that is about to expire.
 * 
 *
 * @version: $Id$
 */
public class RenewCAWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(RenewCAWorker.class);

	/** Flag is keys should be regenerated or not */
	public static final String PROP_RENEWKEYS           = "worker.renewkeys";
	
    @Override
    public void canWorkerRun(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        final CaSessionLocal caSession = ((CaSessionLocal) ejbs.get(CaSessionLocal.class));
        final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = ((CryptoTokenManagementSessionLocal) ejbs
                .get(CryptoTokenManagementSessionLocal.class));

        for (Integer caid : getCAIdsToCheck(false)) {
            CAInfo info = caSession.getCAInfoInternal(caid.intValue());
            try {
                cryptoTokenManagementSession.testKeyPair(getAdmin(), info.getCAToken().getCryptoTokenId(), info.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST));
            } catch (InvalidKeyException | CryptoTokenOfflineException | AuthorizationDeniedException e) {
                throw new ServiceExecutionFailedException("Could not connect to HSM, worker is unable to run.", e);
            }
        }

    }
	
	/**
	 * Worker that makes a query to the Certificate Store about
	 * expiring certificates.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
    @Override
	public ServiceExecutionResult work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
		log.trace(">Worker started");
        final CAAdminSessionLocal caAdminSession = ((CAAdminSessionLocal)ejbs.get(CAAdminSessionLocal.class));
        final CaSessionLocal caSession = ((CaSessionLocal)ejbs.get(CaSessionLocal.class));
		
		// Find CAs with expire date that is less than configured number of days 
		// ahead in the future		
		long millistoexpire = getTimeBeforeExpire();
		long now = new Date().getTime();
		long expiretime = now + millistoexpire;

		// Renew these CAs using the CAAdminSessionBean		
		// Check the "Generate new keys" checkbox so we can pass the correct parameter to CAAdminSessionBean
		List<String> renewedCas = new ArrayList<>();
		for(Integer caid : getCAIdsToCheck(false)) {
			try {
				CAInfo info = caSession.getCAInfoInternal(caid.intValue());
				String caname = null;
				if (info != null) {
					caname = info.getName();
					Date expire = info.getExpireTime(); 
					log.debug("CA "+caname+" expires on "+expire);
					if (expire.before(new Date(expiretime))) {
						// Only try to renew active CAs
						// There should be other monitoring available to check if CAs that should not be off-line are off-line (HealthCheck)
					    try {
					        final boolean createLinkCertificate = isRenewKeys() && (CAInfo.SELFSIGNED == info.getSignedBy());   // We want link certs for new key if CA is selfsigned..
					        caAdminSession.renewCA(getAdmin(), info.getCAId(), isRenewKeys(), null, createLinkCertificate);
					        renewedCas.add(caname);
					    } catch (CryptoTokenOfflineException e) {
					        log.info("Not trying to renew CA because CA and token status are not on-line.");
					    }
					}
				} else {
					log.error(InternalEjbcaResources.getInstance().getLocalizedMessage("services.errorworker.errornoca", caid, caname));
				}
			} catch (CADoesntExistsException e) {
				log.error("Error renewing CA: ", e);
			} catch (AuthorizationDeniedException e) {
				throw new IllegalStateException("Internal admin was denied access.", e);
			}				
		}
		
		log.trace("<Worker ended");
		if(renewedCas.isEmpty()) {
		    return new ServiceExecutionResult(Result.NO_ACTION, "Renew CA worker ran, but no CAs required renewal.");
		} else {
		    return new ServiceExecutionResult(Result.SUCCESS, "The following CAs were renewed by the Renew CA Worker: " + constructNameList(renewedCas));
		}
	}
	
	protected boolean isRenewKeys() {
		return properties.getProperty(PROP_RENEWKEYS,"FALSE").equalsIgnoreCase("TRUE");
	}

  
}
