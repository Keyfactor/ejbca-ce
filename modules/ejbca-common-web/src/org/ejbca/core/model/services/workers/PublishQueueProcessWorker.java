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

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublishingResult;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.FatalPublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExecutionResult;
import org.ejbca.core.model.services.ServiceExecutionResult.Result;

/**
 * Class processing the publisher queue. Can only run on instance in one VM on
 * one node. See method docs below for information about algorithms used.
 * 
 * @version $Id$
 */
public class PublishQueueProcessWorker extends EmailSendingWorker {

    private static final Logger log = Logger.getLogger(PublishQueueProcessWorker.class);

    public static final String PROP_PUBLISHER_IDS = "publisherids";

    /**
     * Semaphore making sure not two identical services run at the same time.
     * This must be decided by serviceName, since we can configure one of these
     * services for every publisher.
     */
    private static HashMap<String, Boolean> runmap = new HashMap<String, Boolean>();

    @Override
    public void canWorkerRun(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        final PublisherSessionLocal publisherSession = ((PublisherSessionLocal) ejbs.get(PublisherSessionLocal.class));
        // Verify that all active publishers can be contacted.
        Object publisherIds = properties.get(PROP_PUBLISHER_IDS);
        if (publisherIds != null) {
            for (String id : StringUtils.split((String) publisherIds, ';')) {
                int publisherId = Integer.valueOf(id);
                BasePublisher publisher = publisherSession.getPublisher(publisherId);
                try {
                    if (publisher != null) {
                        publisher.testConnection();
                    }
                } catch (PublisherConnectionException e) {
                    // Could not connect to publisher - log
                    log.error("Could not connect to publisher destination.", e);
                } catch (FatalPublisherConnectionException e) {
                  //Publishers cannot be contacted, delay this job. 
                  throw new ServiceExecutionFailedException("Publisher test connection failed, see logs for more informetion.", e);
                }
            }
        }

    }
    
    /**
     * Checks if there are any publishing jobs in the publisher queue that should be
     * published.
     * 
     * @see org.ejbca.core.model.services.IWorker#work()
     */
    @Override
    public ServiceExecutionResult work(Map<Class<?>, Object> ejbs) {
        log.trace(">work");
        final PublisherSessionLocal publisherSession = ((PublisherSessionLocal)ejbs.get(PublisherSessionLocal.class));
        final PublisherQueueSessionLocal publisherQueueSession = ((PublisherQueueSessionLocal)ejbs.get(PublisherQueueSessionLocal.class));
        // A semaphore used to not run parallel processing jobs
        boolean running = false;
        synchronized (runmap) {
            Boolean b = runmap.get(this.serviceName);
            if (b != null) {
                running = b.booleanValue();
            }
        }
        PublishingResult publishingResult = new PublishingResult();
        if (!running) {
            try {
                synchronized (runmap) {
                    runmap.put(this.serviceName, Boolean.TRUE);
                }
                Object o = properties.get(PROP_PUBLISHER_IDS);
                if (o != null) {
                    String idstr = (String) o;
                    log.debug("Ids: " + idstr);
                    // Loop through all handled publisher ids and process
                    // anything in the queue
                    String[] ids = StringUtils.split(idstr, ';');
                    if(ids.length == 0) {
                        return new ServiceExecutionResult(Result.NO_ACTION, "Publishing Queue Service " + serviceName + " ran with no active publishers.");
                    }
                    for (int i = 0; i < ids.length; i++) {
                        int publisherId = Integer.valueOf(ids[i]);
                        // Get everything from the queue for this publisher id
                        BasePublisher publisher = publisherSession.getPublisher(publisherId);                  
                        publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(getAdmin(), publisher);
                    }
                } else {
                    log.debug("No publisher ids configured for worker.");
                }
            } finally {
                synchronized (runmap) {
                    runmap.put(this.serviceName, Boolean.FALSE);
                }
            }
        } else {
            log.info(InternalEjbcaResources.getInstance().getLocalizedMessage("services.alreadyrunninginvm", PublishQueueProcessWorker.class.getName()));
        }
        log.trace("<work");
        if (publishingResult.getSuccesses() == 0 && publishingResult.getFailures() == 0) {
            return new ServiceExecutionResult(Result.NO_ACTION,
                    "Publishing Queue Service " + serviceName + " ran, but the publishing queue was either empty or the publisher(s) could not connect.");
        } else {
            if (publishingResult.getFailures() != 0) {
                return new ServiceExecutionResult(Result.FAILURE,
                        "Publishing Queue Service " + serviceName + " ran with " + publishingResult.getFailures() + " failed publishing operations"
                                + (publishingResult.getSuccesses() == 0 ? "."
                                        : " and " + publishingResult.getSuccesses() + " successful publishing operations."));
            } else {
                return new ServiceExecutionResult(Result.SUCCESS, "Publishing Queue Service " + serviceName + " ran with "
                        + publishingResult.getSuccesses() + " successful publishing operations.");
            }
        }
    }

    /**
     * Method that must be implemented by all subclasses to EmailSendingWorker,
     * used to update status of a certificate, user, or similar
     * 
     * @param pk
     *            primary key of object to update
     * @param status
     *            status to update to
     */
    protected void updateStatus(String pk, int status) {
    }

 
}
