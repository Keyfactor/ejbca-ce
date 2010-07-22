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

import java.util.Collection;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
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
    private static final InternalResources intres = InternalResources.getInstance();

    private ICreateCRLSessionLocal createcrlsession = null;

    /** Semaphore that tries to make sure that this CRL creation job does not run several times on the same machine.
     * Since CRL generation can sometimes take a lot of time, this is needed.
     */
	private static boolean running = false;

	/**
	 * Checks if there are any CRL that needs to be updated, and then does the creation.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work() throws ServiceExecutionFailedException {
		// A semaphore used to not run parallel CRL generation jobs if it is slow
		// in generating CRLs, and this job runs very often
		if (!running) {
			try {
				running = true;
			    long polltime = getNextInterval();
			    ICAAdminSessionLocal session = getCAAdminSession();
			    if (session != null) {
			    	// Use true here so the service works the same as before upgrade from 3.9.0 when this function of 
			    	// selecting CAs did not exist, no CA = Any CA.
				    Collection caids = getCAIdsToCheck(true); 
			    	session.createCRLs(getAdmin(), caids, polltime*1000);
			    	session.createDeltaCRLs(getAdmin(), caids, polltime*1000);
			    }			
			} finally {
				running = false;
			}			
		} else {
    		String msg = intres.getLocalizedMessage("services.alreadyrunninginvm", CRLUpdateWorker.class.getName());            	
			log.info(msg);
		}
	}

	
	public ICreateCRLSessionLocal getCreateCRLSession(){
		if(createcrlsession == null){
			try {
	            ICreateCRLSessionLocalHome home = (ICreateCRLSessionLocalHome) getLocator().getLocalHome(ICreateCRLSessionLocalHome.COMP_NAME);
				this.createcrlsession = home.create();
			} catch (CreateException e) {
				log.error(e);
			}
		}
  
		return createcrlsession;
	}
}
