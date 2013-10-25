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
package org.cesecore.certificates.ocsp;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the OcspResponseGenerator that don't involve creating a CA.
 * 
 * @version $Id$
 * 
 */
public class OcspResponseGeneratorSessionTest {

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testWithRandomBytes() throws AuthorizationDeniedException, OCSPException, IOException {
        final int MAX_REQUEST_SIZE = 100000;
        TestOcspResponseGeneratorSessionBean ocspResponseGeneratorSession = new TestOcspResponseGeneratorSessionBean();
        SecureRandom random = new SecureRandom();
        byte[] fakeRequest = new byte[MAX_REQUEST_SIZE + 1];
        random.nextBytes(fakeRequest);
        boolean caught = false;
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        try {
            ocspResponseGeneratorSession.getOcspResponse(fakeRequest, null, null, null, null, auditLogger, transactionLogger);
        } catch (MalformedRequestException e) {
            caught = true;
        }
        assertTrue("MalformedRequestException was not thrown for a request > 100000 bytes.", caught);
    }
 
    private class TestOcspResponseGeneratorSessionBean extends OcspResponseGeneratorSessionBean {

    }
}
