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

import java.util.List;
import org.apache.log4j.Logger;
import org.junit.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.EjbRemoteHelper;

/**
 * @version $Id
 */
public class OcspDataSessionBeanTest {
    private static final Logger log = Logger.getLogger(OcspDataSessionBeanTest.class);

    private final static EjbRemoteHelper ejbRemoteHelper = EjbRemoteHelper.INSTANCE;
    private final static OcspDataSessionRemote ocspDataSessionRemote = ejbRemoteHelper.getRemoteSession(OcspDataSessionRemote.class);
    private final static OcspDataProxySessionRemote ocspDataProxySessionRemote = ejbRemoteHelper.getRemoteSession(OcspDataProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final static Integer certificateAuthOne = 123456789;
    private final static Integer certificateAuthTwo = 234567890;

    @BeforeClass
    public static void setupTestClass() {
        log.trace(">OcspDataSessionBeanTest");

        // Required by testFindExpiringOcpsDataReturnsCorrectResponses
        persistMixofExpiredResponses();
    }

    @AfterClass
    public static void teardownTestClass() {
        removeAllTestOcspResponses();

        log.trace("<OcspDataSessionBeanTest");
    }


    @Test
    public void testFindExpiringOcpsDataReturnsCorrectResponses() {
        log.trace(">testFindExpiringOcpsDataReturnsCorrectResponses");

        List<String> expiredResponses = ocspDataSessionRemote.findExpiringOcpsData(certificateAuthOne, System.currentTimeMillis(), 500, 0);
        assertEquals(1, expiredResponses.size());
        assertTrue(expiredResponses.contains("test-sn-2"));

        log.trace("<testFindExpiringOcpsDataReturnsCorrectResponses");
    }

    /**
     * Add a mix of expired and active Ocsp Responses.
     */
    private static void persistMixofExpiredResponses() {
        log.trace(">persistMixofExpiredResponses");

        Long now = System.currentTimeMillis();
        Long past = now - 3600000; // 1h
        Long future = now + 3600000;

        OcspResponseData certificateAResponseOld = new OcspResponseData("test-id-1", certificateAuthOne, "test-sn-1", past, past, new byte[0]);
        OcspResponseData certificateAResponseNew = new OcspResponseData("test-id-2", certificateAuthOne, "test-sn-1", now, future, new byte[0]);

        OcspResponseData certificateBResponseOld = new OcspResponseData("test-id-3", certificateAuthOne, "test-sn-2", past, future, new byte[0]);
        OcspResponseData certificateBResponseNew = new OcspResponseData("test-id-4", certificateAuthOne, "test-sn-2", now, past, new byte[0]);

        OcspResponseData certificateCResponse = new OcspResponseData("test-id-5", certificateAuthTwo, "test-sn-3", now, past, new byte[0]);

        ocspDataProxySessionRemote.storeOcspData(certificateAResponseOld);
        ocspDataProxySessionRemote.storeOcspData(certificateAResponseNew);
        ocspDataProxySessionRemote.storeOcspData(certificateBResponseOld);
        ocspDataProxySessionRemote.storeOcspData(certificateBResponseNew);
        ocspDataProxySessionRemote.storeOcspData(certificateCResponse);

        log.trace("<persistMixofExpiredResponses");
    }

    /**
     * Remove all the Ocsp Responses that might have been added for the tests.
     */
    private static void removeAllTestOcspResponses() {
        log.trace(">removeAllTestOcspResponses");

        ocspDataProxySessionRemote.deleteOcspDataByCaId(certificateAuthOne);
        ocspDataProxySessionRemote.deleteOcspDataByCaId(certificateAuthTwo);

        log.trace("<removeAllTestOcspResponses");
    }
}
