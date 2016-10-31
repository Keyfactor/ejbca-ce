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

/**
 * Get this node's next log row sequence number.
 * 
 * The sequence number is guaranteed to be unique as long as the read "node identifier"
 * read on first access is unique among the nodes sharing the database.
 * 
 * @version $Id$
 */
public enum NodeSequenceHolder {
    INSTANCE;

    // We only want to use this from IntegrityProtectedDevice
    private NodeSequenceHolder() {}

    private final AtomicLong lastSequenceNumberAtomic = new AtomicLong(-1);
    private final ReentrantLock lockDataBaseUpdate = new ReentrantLock();
    private String nodeId = null;
    
    /** Interface for callback of methods that is invoked once. */
    public interface OnInitCallBack {
        /** @return the current node identifier */
        String getNodeId();
        /** @return the highest known sequence number for the node identifier returned by {@link OnInitCallBack#getNodeId()}*/
        long getMaxSequenceNumberForNode(String nodeId);
    }

    /** @return the node's next log row sequence number. */
    public long getNext(final OnInitCallBack callBack) {
        if (lastSequenceNumberAtomic.get()==-1L) {
            try {
                // Lock threads during initializations of value from the database (only one thread needs to/should do the lookup)
                lockDataBaseUpdate.lock();
                if (lastSequenceNumberAtomic.get()==-1L) {
                    // Note that it very important that the nodeId is cached to avoid gaps in the sequence if the nodeId changes
                    nodeId = callBack.getNodeId();
                    lastSequenceNumberAtomic.set(callBack.getMaxSequenceNumberForNode(nodeId));
                }
            } finally {
                lockDataBaseUpdate.unlock();
            }
        }
        return lastSequenceNumberAtomic.incrementAndGet();
    }

    /** @return the Node Identifier that this sequence number applies to. */
    public String getNodeId() {
        return nodeId;
    }

    /**
     * Trigger a re-read of the nodeId and last sequence number for the node on next call to {@link NodeSequenceHolder#getNext(OnInitCallBack)}.
     * 
     * WARNING: This class is NOT safe to reset in an concurrent environment and this method should only be used from unit tests.
     */
    public void reset() {
        lastSequenceNumberAtomic.set(-1L);
    }
}
