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

import java.util.Collection;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Class managing the updating of CRLs. Loops through the list of CAs to check and generates CRLs and deltaCRLs if needed.
 * 
 * @author Philip Vendil
 * @version $Id$
 */
public class CRLUpdateWorker extends BaseWorker {

    private static final Logger log = Logger.getLogger(CRLUpdateWorker.class);	
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /** Semaphore that tries to make sure that this CRL creation job does not run several times on the same machine.
     * Since CRL generation can sometimes take a lot of time, this is needed.
     */
	private static boolean running = false;

	/**
	 * Checks if there are any CRL that needs to be updated, and then does the creation.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        final PublishingCrlSessionLocal publishingCrlSession = ((PublishingCrlSessionLocal)ejbs.get(PublishingCrlSessionLocal.class));
		// A semaphore used to not run parallel CRL generation jobs if it is slow
		// in generating CRLs, and this job runs very often
		if (!running) {
			try {
				running = true;
			    long polltime = getNextInterval();
			    // Use true here so the service works the same as before upgrade from 3.9.0 when this function of 
			    // selecting CAs did not exist, no CA = Any CA.
			    Collection<Integer> caids = getCAIdsToCheck(true); 
			    publishingCrlSession.createCRLs(getAdmin(), caids, polltime*1000);
			    publishingCrlSession.createDeltaCRLs(getAdmin(), caids, polltime*1000);
			} catch (AuthorizationDeniedException e) {
				log.info("Authorization denied executing service: ", e);
				throw new ServiceExecutionFailedException(e);
			} finally {
				running = false;
			}			
		} else {
    		String msg = intres.getLocalizedMessage("services.alreadyrunninginvm", CRLUpdateWorker.class.getName());            	
			log.info(msg);
		}
	}
}
