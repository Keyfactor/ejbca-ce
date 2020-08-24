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

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.same;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import javax.persistence.EntityManager;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionLocal;
import org.easymock.EasyMock;
import org.ejbca.core.ejb.ocsp.OcspDataSessionLocal;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit test of {@link PublisherQueueSessionBean}
 */
public class PublisherQueueSessionUnitTest {
    
    private final EntityManager entityManagerMock = EasyMock.createStrictMock(EntityManager.class);
    private final NoConflictCertificateStoreSessionLocal noConflictCertificateStoreSessionMock = EasyMock.createStrictMock(NoConflictCertificateStoreSessionLocal.class);
    private final OcspDataSessionLocal ocspDataSessionMock = EasyMock.createStrictMock(OcspDataSessionLocal.class);
    private final PublisherQueueSessionLocal publisherQueueSessionMock = EasyMock.createStrictMock(PublisherQueueSessionLocal.class);
    private final AuthenticationToken adminMock = EasyMock.createStrictMock(AuthenticationToken.class);
    private final BasePublisher publisherMock = EasyMock.createMock(BasePublisher.class);
    
    private final PublisherQueueSessionLocal publisherQueueSession = new PublisherQueueSessionBean(entityManagerMock, noConflictCertificateStoreSessionMock, ocspDataSessionMock, publisherQueueSessionMock);

    @Before
    public void before() {
        reset(entityManagerMock, noConflictCertificateStoreSessionMock, ocspDataSessionMock, publisherQueueSessionMock, adminMock, publisherMock);
    }
    
    /** Creates a PublishingResult with the given ranges of fingerprints for successes and failures. */
    private PublishingResult makePublishingResult(int minSuccessId, int maxSuccessId, int minFailureId, int maxFailureId) {
        final PublishingResult result = new PublishingResult();
        for (int i = minSuccessId; i < maxSuccessId; i++) {
            result.addSuccess("aaaa" + i);
        }
        for (int i = minFailureId; i < maxFailureId; i++) {
            result.addFailure("ffff" + i);
        }
        return result;
    }

    @Test
    public void publishNothing() {
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(0, 0, 0, 0));
        replay(publisherQueueSessionMock);
        assertResult(0, 0, publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(adminMock, publisherMock));
        verify(publisherQueueSessionMock);
    }

    @Test
    public void publishOneChunk() {
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(0, 5, 0, 2)); // 5 successes, 2 failures
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(0, 0, 0, 0));
        replay(publisherQueueSessionMock);
        assertResult(5, 2, publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(adminMock, publisherMock));
        verify(publisherQueueSessionMock);
    }

    @Test
    public void publishTwoChunks() {
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(0, 5, 0, 2)); // 5 successes, 2 failures
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(5, 7, 0, 0)); // 2 successes
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(0, 0, 0, 0));
        replay(publisherQueueSessionMock);
        assertResult(7, 2, publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(adminMock, publisherMock));
        verify(publisherQueueSessionMock);
    }

    /** Tests that publishing only continues when there is at least one result is successful. */
    @Test
    public void publishWithFailureAtEnd() {
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(0, 5, 0, 2)); // 5 successes, 2 failures
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(5, 7, 0, 0)); // 2 successes
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(0, 0, 2, 3)); // 1 failure
        replay(publisherQueueSessionMock);
        assertResult(7, 3, publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(adminMock, publisherMock));
        verify(publisherQueueSessionMock);
    }

    /** Tests that publishing aborts after more than 20 000 successful publishings */
    @Test
    public void tooMuchToPublish() {
        expect(publisherQueueSessionMock.doChunk(same(adminMock), same(publisherMock))).andReturn(makePublishingResult(0, 35_000, 0, 0)); // 35 000 successes
        replay(publisherQueueSessionMock);
        assertResult(35_000, 0, publisherQueueSession.plainFifoTryAlwaysLimit100EntriesOrderByTimeCreated(adminMock, publisherMock));
        verify(publisherQueueSessionMock);
    }

    private void assertResult(int numSuccesses, int numFailures, final PublishingResult actualResult) {
        assertNotNull("Should have a result object", actualResult);
        assertEquals("Wrong number of successful fingerprints", numSuccesses, actualResult.getSuccesses());
        assertEquals("Wrong number of failed fingerprints", numFailures, actualResult.getFailures());
    }
}
