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

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.cesecore.util.QueryResultWrapper;

/**
 * Get this node's next log row sequence number.
 * 
 * @version $Id$
 */
public enum NodeSequenceHolder {
    INSTANCE;

    // We only want to use this from IntegrityProtectedDevice
    private NodeSequenceHolder() {}

    private final AtomicLong lastSequenceNumberAtomic = new AtomicLong(-1);
    private final ReentrantLock lockDataBaseUpdate = new ReentrantLock();

    /** @return the node's next log row sequence number. */
    public long getNext(final EntityManager entityManager, final String nodeId) {
        if (lastSequenceNumberAtomic.get()==-1L) {
            try {
                // Lock threads during initializations of value from the database (only one thread needs to do the lookup)
                lockDataBaseUpdate.lock();
                if (lastSequenceNumberAtomic.get()==-1L) {
                    // Get the latest sequenceNumber from last run from the database..
                    final Query query = entityManager.createQuery("SELECT MAX(a.sequenceNumber) FROM AuditRecordData a WHERE a.nodeId=:nodeId");
                    query.setParameter("nodeId", nodeId);
                    final long value = QueryResultWrapper.getSingleResult(query, Long.valueOf(-1)).longValue();
                    lastSequenceNumberAtomic.set(value);
                }
            } finally {
                lockDataBaseUpdate.unlock();
            }
        }
        return lastSequenceNumberAtomic.incrementAndGet();
    }

    public void reset() {
        lastSequenceNumberAtomic.set(-1L);
    }
}
