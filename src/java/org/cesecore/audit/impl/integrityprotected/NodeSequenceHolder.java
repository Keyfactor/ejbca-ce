/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.audit.impl.integrityprotected;

import java.util.concurrent.locks.ReentrantLock;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.cesecore.util.QueryResultWrapper;

/**
 * Get this node's next log row sequence number.
 * 
 * @version $Id$
 */
public class NodeSequenceHolder {

	// We only want to use this from IntegrityProtectedDevice
	protected NodeSequenceHolder() {}
	
	private volatile long lastSequenceNumber = -1;
	private final ReentrantLock lockSequenceNumber = new ReentrantLock();
	
	public long getNext(final EntityManager entityManager, final String nodeId) {
		try {
			lockSequenceNumber.lock();
			if (lastSequenceNumber == -1) {
				// First time this method is called we check the database for the latest sequenceNumber from last run..
				final Query query = entityManager.createQuery("SELECT MAX(a.sequenceNumber) FROM AuditRecordData a WHERE a.nodeId=:nodeId");
				query.setParameter("nodeId", nodeId);
				lastSequenceNumber = QueryResultWrapper.getSingleResult(query, Long.valueOf(-1)).longValue();
			}
			lastSequenceNumber++;
			return lastSequenceNumber;
		} finally {
			lockSequenceNumber.unlock();
		}
	}
	
	protected void reset() {
		try {
			lockSequenceNumber.lock();
			lastSequenceNumber = -1;
		} finally {
			lockSequenceNumber.unlock();
		}
	}
}
