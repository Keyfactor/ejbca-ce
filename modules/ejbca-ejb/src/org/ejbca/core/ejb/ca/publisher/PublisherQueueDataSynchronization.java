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
package org.ejbca.core.ejb.ca.publisher;

import java.util.Date;

import javax.transaction.Status;
import javax.transaction.Synchronization;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Registered by PublisherQueueDataListener for the transaction associated with the PublisherQueueData
 * entity object.
 * 
 * afterCompletion() is invoked by the transaction manager after transaction is committed (or rolled back). This
 * allows us to take action depending on the outcome of the transaction.
 */
public class PublisherQueueDataSynchronization implements Synchronization {
    
    // Publishing will be executed from queue, as if a Service Worker was being used.
    private static final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ServiceSession"));
    
    private EjbLocalHelper ejbLocalHelper;

    private PublisherSessionLocal publisherSession;
    private PublisherQueueData entity;
    
    public PublisherQueueDataSynchronization(PublisherQueueData entity) {
        this.entity = entity;
        ejbLocalHelper = new EjbLocalHelper();
        publisherSession = ejbLocalHelper.getPublisherSession();
    }
    
    @Override
    public void afterCompletion(int transactionStatus) {
        // PublisherQueueDataEntry has been committed to database. Should be safe to publish.
        if (transactionStatus == Status.STATUS_COMMITTED && entity.isSafeDirectPublishing()) {
            org.ejbca.core.model.ca.publisher.PublisherQueueData queuedData = 
                    new org.ejbca.core.model.ca.publisher.PublisherQueueData(entity.getPk(), new Date(entity.getTimeCreated()), new Date(entity.getLastUpdate()),
                    entity.getPublishStatus(), entity.getTryCounter(), entity.getPublishType(), entity.getFingerprint(), entity.getPublisherId(),
                    entity.getPublisherQueueVolatileData());
            publisherSession.publishQueuedEntry(authenticationToken, entity.getPublisherId(), queuedData);
        }
    }

    @Override
    public void beforeCompletion() {
        // NOOP
    }
}
