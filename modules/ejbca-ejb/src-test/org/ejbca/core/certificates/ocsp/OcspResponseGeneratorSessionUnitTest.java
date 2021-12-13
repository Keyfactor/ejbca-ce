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
package org.ejbca.core.certificates.ocsp;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.easymock.EasyMock;
import org.ejbca.core.ejb.ocsp.OcspResponseGeneratorSessionBean;
import org.junit.Test;

import java.security.SecureRandom;

import static org.junit.Assert.assertTrue;

/**
 * Tests for the OcspResponseGenerator that don't involve creating a CA.
 */
public class OcspResponseGeneratorSessionUnitTest {

    @Test
    public void testWithRandomBytes() throws OCSPException {
        final int MAX_REQUEST_SIZE = 100000;
        TestOcspResponseGeneratorSessionBean ocspResponseGeneratorSession = new TestOcspResponseGeneratorSessionBean();
        SecureRandom random = new SecureRandom();
        byte[] fakeRequest = new byte[MAX_REQUEST_SIZE + 1];
        random.nextBytes(fakeRequest);
        boolean caught = false;
        TransactionCounter.INSTANCE.getTransactionNumber();
        final TransactionLogger transactionLogger = EasyMock.createNiceMock(TransactionLogger.class);
        final AuditLogger auditLogger = EasyMock.createNiceMock(AuditLogger.class);
        try {
            ocspResponseGeneratorSession.getOcspResponse(fakeRequest, null, null, null, null, auditLogger, transactionLogger, false, false);
        } catch (MalformedRequestException e) {
            caught = true;
        }
        assertTrue("MalformedRequestException was not thrown for a request > 100000 bytes.", caught);
    }
 
    private class TestOcspResponseGeneratorSessionBean extends OcspResponseGeneratorSessionBean {

    }
}
