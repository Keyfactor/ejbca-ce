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

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocalHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome;
import org.ejbca.core.ejb.ca.store.CertificateDataLocal;
import org.ejbca.core.ejb.ca.store.CertificateDataPK;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Class processing the publisher queue. Can only run on instance in one VM on one node.
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

	private static boolean running = false;

	/**
	 * Checks if there are any publishings in the publisher queue that should be published.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work() throws ServiceExecutionFailedException {
		log.trace(">work");
		// A semaphore used to not run parallel processing jobs
		if (!running) {
			try {
				running = true;
				Object o = properties.get(PROP_PUBLISHER_IDS);
				if (o != null) {
					String idstr = (String)o;
					log.debug("Ids: "+idstr);
					// Loop through all handled publisher ids and process anything in the queue
					String[] ids = StringUtils.split(idstr, ';');
					for (int i = 0; i < ids.length; i++) {
						int publisherId = Integer.valueOf(ids[i]).intValue();
						// Get everything from the queue for this publisher id
						plainFifoTryAlwaysNoLimit(publisherId);
					}
				} else {
					log.debug("No publisher ids configured for worker.");
				}
			} finally {
				running = false;
			}			
		} else {
    		String msg = intres.getLocalizedMessage("publisher.alreadyrunninginvm", PublishQueueProcessWorker.class.getName());            	
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

	/** Publishing algorithm that is a plain fifo queue. It will select from the database for this particular publisher id, and process 
	 * the record that is returned one by one. The database determines which order the records are returned, usually the reverse order in which they were inserted.
	 * Publishing is tried every time for every pending record returned, with no limit.
	 * 
	 * @param publisherId
	 */
	private void plainFifoTryAlwaysNoLimit(int publisherId) {
		Collection c = getPublishQueueSession().getPendingEntriesForPublisher(publisherId);
		if (log.isDebugEnabled()) {
			log.debug("Found "+c.size()+" certificates to republish for publisher "+publisherId);
		}
		Iterator iter = c.iterator();
		while (iter.hasNext()) {
			PublisherQueueData pqd = (PublisherQueueData)iter.next();
			int id = pqd.getPublisherId();
			if (log.isDebugEnabled()) {
				log.debug("Publishing from queue to publisher: "+id+", fingerprint: "+pqd.getFingerprint()+", pk: "+pqd.getPk());
			}
			// Get the publisher
			BasePublisher publisher = getPublisherSession().getPublisher(getAdmin(), id);
			PublisherQueueVolatileData vold = pqd.getVolatileData();
			CertificateDataLocal certlocal;
			boolean published = false;
			Certificate cert = null;
			try {
				// Read the actual certificate and try to publish it again
				certlocal = getCertificateDataHome().findByPrimaryKey(new CertificateDataPK(pqd.getFingerprint()));
				cert = certlocal.getCertificate();
				published = publisher.storeCertificate(getAdmin(), cert, vold.getUsername(), vold.getPassword(), certlocal.getCaFingerprint(), certlocal.getStatus(), certlocal.getType(), certlocal.getRevocationDate(), certlocal.getRevocationReason(), vold.getExtendedInformation());
			} catch (FinderException e) {
				String msg = intres.getLocalizedMessage("publisher.errornocert", pqd.getFingerprint());            	
				getLogSession().log(getAdmin(), getAdmin().getCaId(), LogConstants.MODULE_SERVICES, new java.util.Date(), vold.getUsername(), null, LogConstants.EVENT_INFO_STORECRL, msg, e);
			} catch (PublisherException e) {
				// Publisher session have already logged this error nicely to getLogSession().log
				log.debug(e.getMessage());
			}
			if (published) {
				// Update with information that publishing was successful
				getPublishQueueSession().updateData(pqd.getPk(), PublisherQueueData.STATUS_SUCCESS, new Date(), pqd.getTryCounter());
			} else {
				// Update with new tryCounter, but same status as before and no timePublished
				int tryCount = pqd.getTryCounter()+1;
				getPublishQueueSession().updateData(pqd.getPk(), pqd.getPublishStatus(), null, tryCount);								
			}
		}
	}
}
