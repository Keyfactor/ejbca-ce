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
import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

/**
 * Remote proxy interface for PublisherQueueSession.
 * @version $Id$
 */
@Remote
public interface PublisherQueueProxySessionRemote {

    void addQueueData(int publisherId, int publishType, String fingerprint,
            PublisherQueueVolatileInformation queueData, int publishStatus) throws CreateException;

    void removeQueueData(java.lang.String pk);

    void updateData(java.lang.String pk, int status, int tryCounter);

    Collection<PublisherQueueData> getEntriesByFingerprint(String fingerprint);

    int[] getPendingEntriesCountForPublisherInIntervals(int publisherId, int[] lowerBounds, int[] upperBounds);

    int getPendingEntriesCountForPublisher(int publisherId);

    Collection<PublisherQueueData> getPendingEntriesForPublisher(int publisherId);
    
    PublishingResult plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(AuthenticationToken admin, int publisherId, BasePublisher publisher);

    /** Removes all entries in PublisherQueueData for a given publishers. Used in tests only */
    void removePublisherQueueEntries(String publisherName);
}
