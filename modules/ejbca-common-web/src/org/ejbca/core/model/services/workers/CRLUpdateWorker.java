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
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExecutionResult;
import org.ejbca.core.model.services.ServiceExecutionResult.Result;

/**
 * Class managing the updating of CRLs. Loops through the list of CAs to check and generates CRLs and deltaCRLs if needed.
 * 
 * @version $Id$
 */
public class CRLUpdateWorker extends BaseWorker {

    private static final Logger log = Logger.getLogger(CRLUpdateWorker.class);	

    /** Semaphore that tries to make sure that this CRL creation job does not run several times on the same machine.
     * Since CRL generation can sometimes take a lot of time, this is needed.
     */
	private static boolean running = false;

    @Override
    public void canWorkerRun(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        final CaSessionLocal caSession = ((CaSessionLocal) ejbs.get(CaSessionLocal.class));
        final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = ((CryptoTokenManagementSessionLocal) ejbs
                .get(CryptoTokenManagementSessionLocal.class));
        Collection<Integer> caIdsToCheck = getCAIdsToCheck(true);
        if(caIdsToCheck.contains(SecConst.ALLCAS)) {
            caIdsToCheck = caSession.getAllCaIds();
        }
        
        for (Integer caid : caIdsToCheck) {
            CAInfo info = caSession.getCAInfoInternal(caid.intValue());
            try {
                cryptoTokenManagementSession.testKeyPair(getAdmin(), info.getCAToken().getCryptoTokenId(), info.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYTEST));
            } catch (InvalidKeyException | CryptoTokenOfflineException | AuthorizationDeniedException e) {
                throw new ServiceExecutionFailedException("Could not connect to HSM, worker is unable to run.", e);
            }
        }
    }
	
	/**
	 * Checks if there are any CRL that needs to be updated, and then does the creation.
	 * @return 
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
    @Override
	public ServiceExecutionResult work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        final PublishingCrlSessionLocal publishingCrlSession = ((PublishingCrlSessionLocal)ejbs.get(PublishingCrlSessionLocal.class));
		// A semaphore used to not run parallel CRL generation jobs if it is slow in generating CRLs, and this job runs very often
        Set<Integer> updatedCas = new HashSet<>();
        Set<Integer> updatedCasDelta = new HashSet<>();
		if (!running) {
			try {
				running = true;
			    long polltime = getNextInterval();
			    // Use true here so the service works the same as before upgrade from 3.9.0 when this function of 
			    // selecting CAs did not exist, no CA = Any CA.
			    Collection<Integer> caids = getCAIdsToCheck(true); 
			    updatedCas.addAll(publishingCrlSession.createCRLs(getAdmin(), caids, polltime*1000));
			    updatedCasDelta.addAll(publishingCrlSession.createDeltaCRLs(getAdmin(), caids, polltime*1000));
			} catch (AuthorizationDeniedException e) {
			    log.error("Internal authentication token was denied access to importing CRLs or revoking certificates.", e);
			} finally {
				running = false;
			}	
            if (updatedCas.isEmpty() && updatedCasDelta.isEmpty()) {
                return new ServiceExecutionResult(Result.NO_ACTION, "CRL Update Worker " + serviceName + " ran, but no CAs needed updating.");
            } else {
                StringBuilder stringBuilder = new StringBuilder("CRL Update Worker " + serviceName + " ran.");
                CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
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
        } else {
            String msg = InternalEjbcaResources.getInstance().getLocalizedMessage("services.alreadyrunninginvm", CRLUpdateWorker.class.getName());
            log.info(msg);
            return new ServiceExecutionResult(Result.NO_ACTION, msg);
        }

	}


}
