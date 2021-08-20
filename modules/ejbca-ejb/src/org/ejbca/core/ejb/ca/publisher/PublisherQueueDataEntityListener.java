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

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.persistence.PostPersist;
import javax.persistence.PostUpdate;
import javax.transaction.TransactionSynchronizationRegistry;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueData;


public class PublisherQueueDataEntityListener {

    private static final Logger log = Logger.getLogger(PublisherQueueDataEntityListener.class);

    @Resource
    TransactionSynchronizationRegistry registry;
    
    @PostConstruct
    public void init() throws NamingException {
        registry = (TransactionSynchronizationRegistry) new InitialContext().lookup("java:comp/TransactionSynchronizationRegistry");        
    }
    
    
    @PostUpdate
    @PostPersist
    public void postUpdate(final PublisherQueueData entity) throws NamingException {
        registry.registerInterposedSynchronization(new PublisherQueueDataSynchronization(entity));
    }
    
    
}
