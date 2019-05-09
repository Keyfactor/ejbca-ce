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
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CACommon;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Replaces CA certificate chains with a pending new rollover certificate chain once the new certificate chain becomes valid.
 *
 * @version: $Id$
 */
public class RolloverWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(RolloverWorker.class);
    /** Internal localization of logs and errors */

    @Override
    public void canWorkerRun(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
        final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = (CryptoTokenManagementSessionLocal) ejbs
                .get(CryptoTokenManagementSessionLocal.class);
        Collection<Integer> caids = getCAIdsToCheck(false);
        if (caids.contains(SecConst.ALLCAS)) {
            for (CAInfo caInfo : caSession.getAuthorizedAndNonExternalCaInfos(getAdmin())) {
                if (caInfo.getStatus() == CAConstants.CA_ACTIVE && caInfo.getIncludeInHealthCheck()) {
                    testKey(cryptoTokenManagementSession, caInfo);
                }
            }
        } else {
            for (int caid : caids) {
                CAInfo caInfo = caSession.getCAInfoInternal(caid);
                testKey(cryptoTokenManagementSession, caInfo);
            }
        }

    }
    
    private void testKey(CryptoTokenManagementSessionLocal cryptoTokenManagementSession, CAInfo caInfo) throws ServiceExecutionFailedException {
        // Verify that the CA's mapped keys exist and optionally that the test-key is usable
        if (caInfo.getStatus() == CAConstants.CA_ACTIVE) {
            final int cryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
            try {
                cryptoTokenManagementSession.testKeyPair(admin, cryptoTokenId,
                        caInfo.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST));
            } catch (InvalidKeyException | CryptoTokenOfflineException | AuthorizationDeniedException e) {
                throw new ServiceExecutionFailedException("Could not establish contact with CA's crypto token.", e);
            }
        }
    }
	
    @Override
    public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        log.trace(">Worker started");
        final CaSessionLocal caSession = ((CaSessionLocal) ejbs.get(CaSessionLocal.class));
        // Find CAs that have a roll over certificate chain that has became valid.
        final Date now = new Date(new Date().getTime() - 10 * 60 * 1000); // delay by 10 minutes to account for clock scew on the clients. TODO make configurable?

        // Roll over these CAs using the CAAdminSessionBean
        Collection<Integer> caids = getCAIdsToCheck(false);
        if (log.isDebugEnabled()) {
            log.debug("Checking " + caids.size() + " CAs for rollover");
        }
        if (caids.contains(SecConst.ALLCAS)) {
            for (CAInfo caInfo : caSession.getAuthorizedAndNonExternalCaInfos(getAdmin())) {
                attemptToPerformRollover(ejbs, caInfo.getCAId(), now);
            }
        } else {
            for (int caid : caids) {
                attemptToPerformRollover(ejbs, caid, now);
            }
        }
        log.trace("<Worker ended");
    }
	
	private void attemptToPerformRollover(Map<Class<?>, Object> ejbs, int caid, Date now) {
        final CaSessionLocal caSession = ((CaSessionLocal)ejbs.get(CaSessionLocal.class));
        final CAAdminSessionLocal caAdminSession = ((CAAdminSessionLocal)ejbs.get(CAAdminSessionLocal.class));
	    try {
            final CACommon ca = caSession.getCA(getAdmin(), caid);
            final List<Certificate> rolloverChain = ca.getRolloverCertificateChain();
            if (rolloverChain != null) {
                final Certificate cert = rolloverChain.get(0);
                if (now.after(CertTools.getNotBefore(cert))) {
                    // Replace certificate chain with the roll over chain
                    if (log.isDebugEnabled()) {
                        log.debug("New certificate of CA "+caid+" is now valid, switching certificate.");
                    }
                    caAdminSession.rolloverCA(getAdmin(), ca.getCAId());
                }
            }
        }  catch (AuthorizationDeniedException e) {
            log.error("Error checking CA for rollover: ", e);
        } catch (CryptoTokenOfflineException e) {
            log.error("Error rolling over CA: ", e);
        }
	}


}
