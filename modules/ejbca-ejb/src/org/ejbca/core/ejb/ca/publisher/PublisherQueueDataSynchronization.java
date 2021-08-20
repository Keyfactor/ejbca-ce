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

import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJB;
import javax.transaction.Status;
import javax.transaction.Synchronization;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueData;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.ca.publisher.BasePublisher;

public class PublisherQueueDataSynchronization implements Synchronization {

    private static final Logger log = Logger.getLogger(PublisherQueueDataSynchronization.class);
    
    private static final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken("Internal Publishing");
    
    @EJB
    PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    PublisherSessionLocal publisherSession;
    @EJB
    CertificateStoreSessionLocal certificateStoreSession;
    
    private PublisherQueueData entity;
    
    PublisherQueueDataSynchronization(PublisherQueueData entity) {
        this.entity = entity;
    }
    
    @Override
    public void afterCompletion(int transactionStatus) {
        if (transactionStatus == Status.STATUS_COMMITTED) {
            log.info("### Transaction committed");
            final BasePublisher publisher = publisherSession.getPublisher(entity.getPublisherId());
            if (!publisher.getOnlyUseQueue()) {
                final List<BasePublisher> publisherList = new ArrayList<>();
                publisherList.add(publisher);
                final CertificateDataWrapper certificateDataWrapper = certificateStoreSession.getCertificateData(entity.getFingerprint());            
                publisherQueueSession.publishCertificateNonTransactionalInternal(publisherList, authenticationToken, certificateDataWrapper, 
                        entity.getPublisherQueueVolatileData().getPassword(), entity.getPublisherQueueVolatileData().getUserDN(), entity.getPublisherQueueVolatileData().getExtendedInformation());
            }
        } else if (transactionStatus == Status.STATUS_ROLLEDBACK) {
            log.info("### Transaction rolled back");
        }
    }

    @Override
    public void beforeCompletion() {
        // NOOP
    }
    
}
