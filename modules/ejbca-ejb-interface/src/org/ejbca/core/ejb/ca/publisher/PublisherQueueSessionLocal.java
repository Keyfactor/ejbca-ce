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

import java.util.Collection;
import java.util.List;

import javax.ejb.CreateException;
import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileInformation;

/**
 * Local interface for PublisherQueueSession.
 * @version $Id$
 */
@Local
public interface PublisherQueueSessionLocal {
    /**
     * Adds an entry to the publisher queue.
     *
     * @param publisherId the publisher that this should be published to
     * @param publishType the type of entry it is, {@link PublisherQueueData#PUBLISH_TYPE_CERT} or CRL
     * @throws CreateException if the entry can not be created
     */
    void addQueueData(int publisherId, int publishType, String fingerprint,
            PublisherQueueVolatileInformation queueData, int publishStatus) throws CreateException;

    /** Removes an entry from the publisher queue. */
    void removeQueueData(String pk);

    /**
     * Finds all entries with status PublisherQueueData.STATUS_PENDING for a
     * specific publisherId.
     * 
     * @return Collection of PublisherQueueData, never null
     */
    Collection<PublisherQueueData> getPendingEntriesForPublisher(int publisherId);

    /**
     * Gets the number of pending entries for a publisher.
     * @param publisherId The publisher to count the number of pending entries for.
     * @return The number of pending entries.
     */
    int getPendingEntriesCountForPublisher(int publisherId);

    /**
     * Gets an array with the number of new pending entries for a publisher in each intervals specified by 
     * <i>lowerBounds</i> and <i>upperBounds</i>. 
     * 
     * The interval is defined as from lowerBounds[i] to upperBounds[i] and the unit is seconds from now. 
     * A negative value results in no boundary.
     * 
     * @param publisherId The publisher to count the number of pending entries for.
     * @return Array with the number of pending entries corresponding to each element in <i>interval</i>.
     */
    int[] getPendingEntriesCountForPublisherInIntervals(int publisherId, int[] lowerBounds, int[] upperBounds);

    /**
     * Finds all entries with status PublisherQueueData.STATUS_PENDING for a
     * specific publisherId.
     * 
     * @param orderBy
     *            order by clause for the SQL to the database, for example
     *            "order by timeCreated desc".
     * @return Collection of PublisherQueueData, never null
     */
    Collection<PublisherQueueData> getPendingEntriesForPublisherWithLimit(int publisherId, int limit, int timeout, String orderBy);

    /**
     * Finds all entries for a specific fingerprint.
     * 
     * @return Collection of PublisherQueueData, never null
     */
    Collection<PublisherQueueData> getEntriesByFingerprint(String fingerprint);

    /**
     * Updates a record with new status
     * 
     * @param pk primary key of data entry
     * @param status status from PublisherQueueData.STATUS_SUCCESS etc, or -1 to not update status
     * @param tryCounter an updated try counter, or -1 to not update counter
     */
    void updateData(String pk, int status, int tryCounter);

    /**
     * Intended for use from PublishQueueProcessWorker.
     * 
     * Publishing algorithm that is a plain fifo queue, but limited to selecting entries to republish at 100 records at a time. It will select from the database for this particular publisher id, and process 
     * the record that is returned one by one. The records are ordered by date, descending so the oldest record is returned first. 
     * Publishing is tried every time for every record returned, with no limit.
     * Repeat this process as long as we actually manage to publish something this is because when publishing starts to work we want to publish everything in one go, if possible.
     * However we don't want to publish more than 20000 certificates each time, because we want to commit to the database some time as well.
     * Now, the OCSP publisher uses a non-transactional data source so it commits every time so...
     */
    void plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(AuthenticationToken admin, int publisherId, BasePublisher publisher);

    
    /** Publishers do not run a part of regular transactions and expect to run in auto-commit mode. */
	boolean storeCertificateNonTransactional(BasePublisher publisher, AuthenticationToken admin, CertificateDataWrapper cert, String username, String password, String userDN,
    		String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId,
    		long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException;

    /** Publishers do not run as part of regular transactions and expect to run in auto-commit mode. */
	boolean storeCRLNonTransactional(BasePublisher publisher, AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException;

    /**
     * Publishers do not run as part of regular transactions and expect to run in auto-commit mode.
     * This method is invoked locally to publish to multiple publishers in parallel.
     * 
     * The implementing method returns the result in the same order as the publishers are provided.
     * Each result Object is either a PublisherException (if the publishing failed) or a Boolean.TRUE (if the publishing succeeded).
     */
    List<Object> storeCertificateNonTransactionalInternal(List<BasePublisher> publishers, AuthenticationToken admin, CertificateDataWrapper certWrapper, String username, String password, String userDN,
            String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId,
            long lastUpdate, ExtendedInformation extendedinformation);
	
    /** Publishers digest queues in transaction-based "chunks". */
	int doChunk(AuthenticationToken admin, int publisherId, BasePublisher publisher);
}
