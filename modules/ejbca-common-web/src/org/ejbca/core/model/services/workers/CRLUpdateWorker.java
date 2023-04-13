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

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExecutionResult;
import org.ejbca.core.model.services.ServiceExecutionResult.Result;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.collections4.SetUtils;

/**
 * Class managing the updating of CRLs. Loops through the list of CAs to check and generates CRLs and deltaCRLs if needed.
 */
public class CRLUpdateWorker extends BaseWorker {

    private static final Logger log = Logger.getLogger(CRLUpdateWorker.class);	

    /** Semaphore that tries to make sure that this CRL creation job does not run several times on the same machine.
     * Since CRL generation can sometimes take a lot of time, this is needed.
     */
    private static Set<Integer> lockedCas = ConcurrentHashMap.newKeySet();

    /**
     * <p>Check if the {@link CRLUpdateWorker} can run on this node.
     *
     * <p>Checks if the CRL signing key for active CA(s) are accessible.
     *
     * @param ejbs A map between Local EJB interface classes and their injected stub.
     * @throws ServiceExecutionFailedException if the worker cannot run on this node
     */
    @Override
    public void canWorkerRun(final Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
        final CryptoTokenManagementSessionLocal cryptoTokenSession = (CryptoTokenManagementSessionLocal) ejbs.get(CryptoTokenManagementSessionLocal.class);

        Collection<Integer> caIds = getAllCAIdsToCheck(caSession, true);

        for (Integer caId : caIds) {
            try {
                final CAInfo caInfo = caSession.getCAInfo(getAdmin(), caId);
                if (caInfo == null) {
                    log.warn("CA with CA id " + caId + " not found.");
                    continue;
                }
                if (caInfo.getStatus() != CAConstants.CA_ACTIVE) {
                    continue;
                }
                cryptoTokenSession.testKeyPair(getAdmin(),
                        caInfo.getCAToken().getCryptoTokenId(),
                        caInfo.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN));
            } catch (AuthorizationDeniedException | InvalidKeyException e) {
                throw new ServiceExecutionFailedException(e);
            } catch (CryptoTokenOfflineException e) {
                // handled gracefully in publishCrlSessionBean
                log.warn("Crytotoken is offline for CA with CA id " + caId + ".");
                continue;
            }
        }
    }
	
	/**
	 * Checks if there are any CRL that needs to be updated, and then does the creation.
	 * @return a {@link ServiceExecutionResult} containing the result of the execution.
	 * 
	 * {@see org.ejbca.core.model.services.IWorker#work()}
	 */
    @Override
	public ServiceExecutionResult work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        final PublishingCrlSessionLocal publishingCrlSession = ((PublishingCrlSessionLocal)ejbs.get(PublishingCrlSessionLocal.class));
        CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);

        // A semaphore used to not run parallel CRL generation jobs if it is slow in generating CRLs, and this job runs very often
        Set<Integer> updatedCas = new HashSet<>();
        Set<Integer> updatedCasDelta = new HashSet<>();
        Set<Integer> caids = new HashSet<>(getAllCAIdsToCheck(caSession, true));
        if (lock(caids)) {
            try {
                long polltime = getNextInterval();
                // Use true here so the service works the same as before upgrade from 3.9.0 when this function of
                // selecting CAs did not exist, no CA = Any CA.
                updatedCas.addAll(publishingCrlSession.createCRLs(getAdmin(), caids, polltime*1000));
                updatedCasDelta.addAll(publishingCrlSession.createDeltaCRLs(getAdmin(), caids, polltime*1000));
            } catch (AuthorizationDeniedException e) {
                log.error("Internal authentication token was denied access to importing CRLs or revoking certificates.", e);
            } finally {
                releaseLock(caids);
            }
            if (updatedCas.isEmpty() && updatedCasDelta.isEmpty()) {
                return new ServiceExecutionResult(Result.NO_ACTION, "CRL Update Worker " + serviceName + " ran, but no CAs needed updating.");
            } else {
                StringBuilder stringBuilder = new StringBuilder("CRL Update Worker " + serviceName + " ran.");
                Map<Integer, String> caNameMap = caSession.getCAIdToNameMap();
                if (!updatedCas.isEmpty()) {
                    List<String> caNames = new ArrayList<>();
                    for (int caid : updatedCas) {
                        caNames.add(caNameMap.get(caid));
                    }
                    stringBuilder.append(" The following CA generated new CRLs: " + constructNameList(caNames) + ".");
                }
                if (!updatedCasDelta.isEmpty()) {
                    List<String> deltaCaNames = new ArrayList<>();
                    for (int caid : updatedCasDelta) {
                        deltaCaNames.add(caNameMap.get(caid));
                    }
                    stringBuilder.append(" The following CA generated new delta CRLs: " + constructNameList(deltaCaNames) + ".");
                }
                return new ServiceExecutionResult(Result.SUCCESS, stringBuilder.toString());

            }
        }else {
            String msg = InternalEjbcaResources.getInstance().getLocalizedMessage("services.caconflict", serviceName);
            log.info(msg);
            return new ServiceExecutionResult(Result.NO_ACTION, msg);
        }
	}

    /**
     * Mark a set of CAs for CRL generation.
     *
     * @param casToLock a set of CAs to generate CRLs for
     * @return true if a lock could be obtained for all CAs
     */
    private static synchronized boolean lock(final Set<Integer> casToLock) {
        if (SetUtils.intersection(lockedCas, casToLock).isEmpty()) {
            return lockedCas.addAll(casToLock);
        }
        return false;
    }

    /**
     * Release the lock for a set of CAs.
     *
     * @param casToUnlock a set of CAs for which CRL generation has completed.
     */
    private static synchronized void releaseLock(final Set<Integer> casToUnlock) {
        lockedCas.removeAll(casToUnlock);
    }
}
