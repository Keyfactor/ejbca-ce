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
package org.ejbca.core.ejb.ca.publisher;

import javax.ejb.Remote;

/**
 * Local interface for PublisherQueueSession.
 */
@Remote
public interface PublisherQueueSessionLocal {
    /**
     * Adds an entry to the publisher queue.
     * 
     * @param publisherId
     *            the publisher that this should be published to
     * @param publishType
     *            the type of entry it is,
     *            {@link PublisherQueueData#PUBLISH_TYPE_CERT} or CRL
     * @throws CreateException
     *             if the entry can not be created
     */
    public void addQueueData(int publisherId, int publishType, java.lang.String fingerprint,
            org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData queueData, int publishStatus) throws javax.ejb.CreateException;

    /**
     * Removes an entry from the publisher queue.
     */
    public void removeQueueData(java.lang.String pk);

    /**
     * Finds all entries with status PublisherQueueData.STATUS_PENDING for a
     * specific publisherId.
     * 
     * @return Collection of PublisherQueueData, never null
     */
    public java.util.Collection getPendingEntriesForPublisher(int publisherId);

    /**
     * Gets the number of pending entries for a publisher.
     * 
     * @param publisherId
     *            The publisher to count the number of pending entries for.
     * @return The number of pending entries.
     */
    public int getPendingEntriesCountForPublisher(int publisherId);

    /**
     * Gets an array with the number of new pending entries for a publisher in
     * each intervals specified by <i>lowerBounds</i> and <i>upperBounds</i>.
     * The interval is defined as from lowerBounds[i] to upperBounds[i] and the
     * unit is seconds from now. A negative value results in no boundary.
     * 
     * @param publisherId
     *            The publisher to count the number of pending entries for.
     * @return Array with the number of pending entries corresponding to each
     *         element in <i>interval</i>.
     */
    public int[] getPendingEntriesCountForPublisherInIntervals(int publisherId, int[] lowerBounds, int[] upperBounds);

    /**
     * Finds all entries with status PublisherQueueData.STATUS_PENDING for a
     * specific publisherId.
     * 
     * @param orderBy
     *            order by clause for the SQL to the database, for example
     *            "order by timeCreated desc".
     * @return Collection of PublisherQueueData, never null
     */
    public java.util.Collection getPendingEntriesForPublisherWithLimit(int publisherId, int limit, int timeout, java.lang.String orderBy);

    /**
     * Finds all entries for a specific fingerprint.
     * 
     * @return Collection of PublisherQueueData, never null
     */
    public java.util.Collection getEntriesByFingerprint(java.lang.String fingerprint);

    /**
     * Updates a record with new status
     * 
     * @param pk
     *            primary key of data entry
     * @param status
     *            status from PublisherQueueData.STATUS_SUCCESS etc, or -1 to
     *            not update status
     * @param tryCounter
     *            an updated try counter, or -1 to not update counter
     */
    public void updateData(java.lang.String pk, int status, int tryCounter);
}
