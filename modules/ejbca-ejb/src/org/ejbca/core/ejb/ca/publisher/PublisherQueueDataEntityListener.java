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

import javax.annotation.Resource;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.persistence.PostPersist;
import javax.persistence.PostUpdate;
import javax.transaction.TransactionSynchronizationRegistry;


public class PublisherQueueDataEntityListener {

    @Resource
    TransactionSynchronizationRegistry registry;
    
    @PostUpdate
    @PostPersist
    public void postUpdate(final PublisherQueueData entity) throws NamingException {
        if (registry == null) {
            registry = (TransactionSynchronizationRegistry) new InitialContext().lookup("java:comp/TransactionSynchronizationRegistry");
        }
        registry.registerInterposedSynchronization(new PublisherQueueDataSynchronization(entity));
    }
    
}
