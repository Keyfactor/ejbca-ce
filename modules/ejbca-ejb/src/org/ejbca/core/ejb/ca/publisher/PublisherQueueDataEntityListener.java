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

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.persistence.PostPersist;
import javax.persistence.PostUpdate;
import javax.transaction.TransactionSynchronizationRegistry;

import org.apache.log4j.Logger;


public class PublisherQueueDataEntityListener {

    private static final Logger log = Logger.getLogger(PublisherQueueDataEntityListener.class);

    // @Resource Annotation causes lookup failure on WF10. Lookup with JNDI instead
    TransactionSynchronizationRegistry registry;
    
    @PostUpdate
    @PostPersist
    public void postUpdate(final PublisherQueueData entity) throws NamingException {
        try {
            registry = (TransactionSynchronizationRegistry) new InitialContext().lookup("java:comp/TransactionSynchronizationRegistry");
        } catch (NamingException e) {
            log.info("TransactionSynchronizationRegistry JNDI lookup failed for java:comp/TransactionSynchronizationRegistry\n"
                    + "Using java:comp/env/TransactionSynchronizationRegistry instead");
            registry = (TransactionSynchronizationRegistry) new InitialContext().lookup("java:comp/env/TransactionSynchronizationRegistry");
            throw new IllegalStateException(e);
        }
        registry.registerInterposedSynchronization(new PublisherQueueDataSynchronization(entity));
    }
}
