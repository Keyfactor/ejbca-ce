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

import java.util.HashMap;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Class processing the publisher queue. Can only run on instance in one VM on
 * one node. See method docs below for information about algorithms used.
 * 
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class PublishQueueProcessWorker extends EmailSendingWorker {

    private static final Logger log = Logger.getLogger(PublishQueueProcessWorker.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    public static final String PROP_PUBLISHER_IDS = "publisherids";

    /**
     * Semaphore making sure not two identical services run at the same time.
     * This must be decided by serviceName, since we can configure one of these
     * services for every publisher.
     */
    private static HashMap runmap = new HashMap();

    /**
     * Checks if there are any publishings in the publisher queue that should be
     * published.
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
                running = ((Boolean) o).booleanValue();
            }
        }
        if (!running) {
            try {
                synchronized (runmap) {
                    runmap.put(this.serviceName, Boolean.valueOf(true));
                }
                Object o = properties.get(PROP_PUBLISHER_IDS);
                if (o != null) {
                    String idstr = (String) o;
                    log.debug("Ids: " + idstr);
                    // Loop through all handled publisher ids and process
                    // anything in the queue
                    String[] ids = StringUtils.split(idstr, ';');
                    for (int i = 0; i < ids.length; i++) {
                        int publisherId = Integer.valueOf(ids[i]).intValue();
                        // Get everything from the queue for this publisher id
                        BasePublisher publisher = getPublisherSession().getPublisher(getAdmin(), publisherId);
                        getPublisherQueueSession().plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(getAdmin(), publisherId, publisher);
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
