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

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

/**
 * @version $Id$
 *
 */

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "PublisherQueueProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherQueueProxySessionBean implements PublisherQueueProxySessionRemote {

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;


    @EJB
    private PublisherQueueSessionLocal queueSession;
    
    @Override
    public void addQueueData(int publisherId, int publishType, String fingerprint,
            PublisherQueueVolatileInformation queueData, int publishStatus) throws CreateException {
        queueSession.addQueueData(publisherId, publishType, fingerprint, queueData, publishStatus);
    }

    @Override
    public void removeQueueData(java.lang.String pk) {
        queueSession.removeQueueData(pk);
    }

    @Override
    public void updateData(java.lang.String pk, int status, int tryCounter) {
        queueSession.updateData(pk, status, tryCounter);
    }

    @Override
    public Collection<PublisherQueueData> getEntriesByFingerprint(String fingerprint) {
        return queueSession.getEntriesByFingerprint(fingerprint);
    }

    @Override
    public int[] getPendingEntriesCountForPublisherInIntervals(int publisherId, int[] lowerBounds, int[] upperBounds) {
        return queueSession.getPendingEntriesCountForPublisherInIntervals(publisherId, lowerBounds, upperBounds);
    }

    @Override
    public int getPendingEntriesCountForPublisher(int publisherId) {
        return queueSession.getPendingEntriesCountForPublisher(publisherId);
    }

    @Override
    public Collection<PublisherQueueData> getPendingEntriesForPublisher(int publisherId) {
        return queueSession.getPendingEntriesForPublisher(publisherId);
    }
    
}
