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
import java.util.HashMap;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocalHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome;
import org.ejbca.core.ejb.ca.store.CRLDataLocal;
import org.ejbca.core.ejb.ca.store.CRLDataPK;
import org.ejbca.core.ejb.ca.store.CertificateDataLocal;
import org.ejbca.core.ejb.ca.store.CertificateDataPK;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Class processing the publisher queue. Can only run on instance in one VM on one node.
 * See method docs below for information about algorithms used.
 * 
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class PublishQueueProcessWorker extends EmailSendingWorker {

    private static final Logger log = Logger.getLogger(PublishQueueProcessWorker.class);	

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    public static final String PROP_PUBLISHER_IDS = "publisherids";
    
    private IPublisherQueueSessionLocal pqsession = null;
    private IPublisherSessionLocal psession = null;

    /** Semaphore making sure not two identical services run at the same time. 
     * This must be decided by serviceName, since we can configure one of these services for every publisher. */
	private static HashMap runmap = new HashMap();

	/**
	 * Checks if there are any publishings in the publisher queue that should be published.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work() throws ServiceExecutionFailedException {
		log.trace(">work");
		// A semaphore used to not run parallel processing jobs
		boolean running = false;
		synchronized (runmap) {
			Object o = runmap.get(this.serviceName);
			if (o != null) {
				running = ((Boolean)o).booleanValue();				
			}
		}
		if (!running) {
			try {
				synchronized (runmap) {
					runmap.put(this.serviceName, Boolean.valueOf(true));
				}
				Object o = properties.get(PROP_PUBLISHER_IDS);
				if (o != null) {
					String idstr = (String)o;
					log.debug("Ids: "+idstr);
					// Loop through all handled publisher ids and process anything in the queue
					String[] ids = StringUtils.split(idstr, ';');
					for (int i = 0; i < ids.length; i++) {
						int publisherId = Integer.valueOf(ids[i]).intValue();
						// Get everything from the queue for this publisher id
						plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(publisherId);
					}
				} else {
					log.debug("No publisher ids configured for worker.");
				}
			} finally {
				synchronized (runmap) {
					runmap.put(this.serviceName, Boolean.valueOf(false));
				}
			}			
		} else {
    		String msg = intres.getLocalizedMessage("services.alreadyrunninginvm", PublishQueueProcessWorker.class.getName());            	
			log.info(msg);
		}
		log.trace("<work");
	}

	/** Method that must be implemented by all subclasses to EmailSendingWorker, used to update status of 
	 * a certificate, user, or similar
	 * @param pk primary key of object to update
	 * @param status status to update to 
	 */
	protected void updateStatus(String pk, int status) {
	}
	
	public IPublisherQueueSessionLocal getPublishQueueSession(){
		if(pqsession == null){
			try {
				IPublisherQueueSessionLocalHome home = (IPublisherQueueSessionLocalHome) getLocator().getLocalHome(IPublisherQueueSessionLocalHome.COMP_NAME);
				this.pqsession = home.create();
			} catch (CreateException e) {
				log.error(e);
			}
		} 
		return pqsession;
	}

	public IPublisherSessionLocal getPublisherSession(){
		if(psession == null){
			try {
				IPublisherSessionLocalHome home = (IPublisherSessionLocalHome) getLocator().getLocalHome(IPublisherSessionLocalHome.COMP_NAME);
				this.psession = home.create();
			} catch (CreateException e) {
				log.error(e);
			}
		} 
		return psession;
	}

	/** Publishing algorithm that is a plain fifo queue, but limited to selecting entries to republish at 100 records at a time. It will select from the database for this particular publisher id, and process 
	 * the record that is returned one by one. The records are ordered by date, descending so the oldest record is returned first. 
	 * Publishing is tried every time for every record returned, with no limit.
     * Repeat this process as long as we actually manage to publish something this is because when publishing starts to work we want to publish everything in one go, if possible.
     * However we don't want to publish more than 20000 certificates each time, because we want to commit to the database some time as well.
     * Now, the OCSP publisher uses a non-transactional data source so it commits every time so...
	 * 
	 * @param publisherId
	 * @throws PublisherException 
	 */
	private void plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(int publisherId) {
		int successcount = 0;
		// Repeat this process as long as we actually manage to publish something
		// this is because when publishing starts to work we want to publish everything in one go, if possible.
		// However we don't want to publish more than 5000 certificates each time, because we want to commit to the database some time as well.
		int totalcount = 0;
		do {
			Collection c = getPublishQueueSession().getPendingEntriesForPublisherWithLimit(publisherId, 100, 60, "order by timeCreated");
			successcount = doPublish(publisherId, c);
			totalcount += successcount;
			log.debug("Totalcount="+totalcount);
		} while ( (successcount > 0) && (totalcount < 20000) );
	}

	/**
	 * @param publisherId
	 * @param c
	 * @return how many publishes that succeeded
	 * @throws PublisherException 
	 */
	private int doPublish(int publisherId, Collection c) {
		if (log.isDebugEnabled()) {
			log.debug("Found "+c.size()+" certificates to republish for publisher "+publisherId);
		}
		int successcount = 0;
		int failcount = 0;
		// Get the publisher. Beware this can be null!
		BasePublisher publisher = getPublisherSession().getPublisher(getAdmin(), publisherId);
		Iterator iter = c.iterator();
		while (iter.hasNext()) {
			PublisherQueueData pqd = (PublisherQueueData)iter.next();
			String fingerprint = pqd.getFingerprint();
			int publishType = pqd.getPublishType();
			if (log.isDebugEnabled()) {
				log.debug("Publishing from queue to publisher: "+publisherId+", fingerprint: "+fingerprint+", pk: "+pqd.getPk()+", type: "+publishType);
			}
			PublisherQueueVolatileData voldata = pqd.getVolatileData();
			String username = null;
			String password = null;
			ExtendedInformation ei = null;
			String userDataDN = null;
			if (voldata != null) {
				username = voldata.getUsername();
				password = voldata.getPassword();
				ei = voldata.getExtendedInformation();
				userDataDN = voldata.getUserDN();
			}
			boolean published = false;
			
			try {
				if (publishType == PublisherQueueData.PUBLISH_TYPE_CERT) {
					if (log.isDebugEnabled()) {
						log.debug("Publishing Certificate");
					}
					if (publisher != null) {
						// Read the actual certificate and try to publish it again
						CertificateInfo info = getCertificateSession().getCertificateInfo(getAdmin(), fingerprint);
						CertificateDataLocal certlocal = getCertificateDataHome().findByPrimaryKey(new CertificateDataPK(fingerprint));
						published = publisher.storeCertificate(getAdmin(), certlocal.getCertificate(), username, password, userDataDN, info.getCAFingerprint(), info.getStatus(), info.getType(), info.getRevocationDate().getTime(), info.getRevocationReason(), info.getTag(), info.getCertificateProfileId(), info.getUpdateTime().getTime(), ei);
					} else {
						String msg = intres.getLocalizedMessage("publisher.nopublisher", publisherId);            	
						log.info(msg);
					}
				} else if (publishType == PublisherQueueData.PUBLISH_TYPE_CRL) {
					if (log.isDebugEnabled()) {
						log.debug("Publishing CRL");
					}
					CRLDataLocal crllocal = getCRLDataHome().findByPrimaryKey(new CRLDataPK(fingerprint));
					published = publisher.storeCRL(getAdmin(), crllocal.getCRLBytes(), crllocal.getCaFingerprint(), userDataDN);
				} else {
					String msg = intres.getLocalizedMessage("publisher.unknowntype", publishType);            	
					log.error(msg);					
				}
			} catch (FinderException e) {
				String msg = intres.getLocalizedMessage("publisher.errornocert", fingerprint);            	
				getLogSession().log(getAdmin(), getAdmin().getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), username, null, LogConstants.EVENT_INFO_STORECERTIFICATE, msg, e);
			} catch (PublisherException e) {
				// Publisher session have already logged this error nicely to getLogSession().log
				log.debug(e.getMessage());
				// We failed to publish, update failcount so we can break early if nothing succeeds but everything fails.
				failcount++;
			}				

			
			if (published) {
				if (publisher.getKeepPublishedInQueue()) {
					// Update with information that publishing was successful
					getPublishQueueSession().updateData(pqd.getPk(), PublisherQueueData.STATUS_SUCCESS, pqd.getTryCounter());
				} else {
					// We are done with this one.. nuke it!
					getPublishQueueSession().removeQueueData(pqd.getPk());
				}
				successcount++; // jipeee update success counter
			} else {
				// Update with new tryCounter, but same status as before
				int tryCount = pqd.getTryCounter()+1;
				getPublishQueueSession().updateData(pqd.getPk(), pqd.getPublishStatus(), tryCount);								
			}
			// If we don't manage to publish anything, but fails on all the first ten ones we expect that this publisher is dead for now. We don't have to try with every record.
			if ( (successcount == 0) && (failcount > 10) ) {
				if (log.isDebugEnabled()) {
					log.debug("Breaking out of publisher loop because everything seems to fail (at least the first 10 entries)");
				}
				break;
			}
		}
		if (log.isDebugEnabled()) {
			log.debug("Returning from publisher with "+successcount+" entries published successfully.");
		}
		return successcount;
	}
	
	
}
