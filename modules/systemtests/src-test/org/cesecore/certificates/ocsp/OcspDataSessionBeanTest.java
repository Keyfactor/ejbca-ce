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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ocsp.OcspDataSessionRemote;
import org.junit.After;
import org.junit.Test;

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

    @After
    public void removeData() {
        log.trace(">removeData");
        removeAllTestOcspResponses();
        log.trace("<removeData");
    }

    // Remote Session methods

    @Test
    public void testFindExpiringOcpsDataReturnsCorrectResponses() throws InterruptedException {
        log.trace(">testFindExpiringOcpsDataReturnsCorrectResponses");

        persistMixofExpiredResponses();
        Thread.sleep(2000);

        List<String> expiredResponses = ocspDataSessionRemote.findExpiringOcpsData(certificateAuthOne, System.currentTimeMillis(), 500, 0);
        assertEquals(1, expiredResponses.size());
        assertTrue(expiredResponses.contains("test-sn-2"));

        log.trace("<testFindExpiringOcpsDataReturnsCorrectResponses");
    }

    @Test
    public void testFindOcspDataByCaId() throws InterruptedException {
        log.trace(">testfindOcspDataByCaId");

        Long time = System.currentTimeMillis();

        OcspResponseData responseA = new OcspResponseData("id-find-by-ca-1", certificateAuthOne, "sn-find-by-ca-1", time, time, new byte[0]);
        OcspResponseData responseB = new OcspResponseData("id-find-by-ca-2", certificateAuthOne, "sn-find-by-ca-2", time, time, new byte[0]);
        ocspDataProxySessionRemote.storeOcspData(responseA);
        ocspDataProxySessionRemote.storeOcspData(responseB);
        Thread.sleep(1000);

        assertEquals(2, ocspDataSessionRemote.findOcspDataByCaId(certificateAuthOne).size());

        log.trace("<testfindOcspDataByCaId");
    }

    @Test
    public void testFindOcspDataByCaIdSerialNumber() throws InterruptedException {
        log.trace(">testFindOcspDataByCaIdSerialNumber");

        Long now = System.currentTimeMillis();
        Long future = now + 360000;

        OcspResponseData response = new OcspResponseData("id-find-by-ca-serial-1", certificateAuthOne, "sn-find-by-ca-serial-1", now, future, new byte[0]);
        ocspDataProxySessionRemote.storeOcspData(response);
        Thread.sleep(2000);

        OcspResponseData found = ocspDataSessionRemote.findOcspDataByCaIdSerialNumber(response.getCaId(), response.getSerialNumber());
        OcspResponseData notFound = ocspDataSessionRemote.findOcspDataByCaIdSerialNumber(certificateAuthOne, "sn-find-by-ca-serial-2");

        assertNotNull(found);
        assertEquals("sn-find-by-ca-serial-1", found.getSerialNumber());

        assertNull(notFound);

        log.trace("<testFindOcspDataByCaIdSerialNumber");
    }

    @Test
    public void testFindOcspDataById() throws InterruptedException {
        log.trace(">testFindOcspDataById");

        Long now = System.currentTimeMillis();

        OcspResponseData response = new OcspResponseData("id-find-by-id-1", certificateAuthOne, "sn-find-by-id-1", now, now, new byte[0]);
        ocspDataProxySessionRemote.storeOcspData(response);
        Thread.sleep(1000);

        OcspResponseData found = ocspDataSessionRemote.findOcspDataById(response.getId());

        assertNotNull(found);
        assertEquals(response.getSerialNumber(), found.getSerialNumber());

        log.trace("<testFindOcspDataById");
    }

    @Test
    public void testFindOcspDataBySerialNumber() throws InterruptedException {
        log.trace(">testFindOcspDataBySerialNumber");

        Long now = System.currentTimeMillis();

        OcspResponseData responseA = new OcspResponseData("id-find-by-id-1", certificateAuthOne, "sn-find-by-id-1", now, now, new byte[0]);
        OcspResponseData responseB = new OcspResponseData("id-find-by-id-2", certificateAuthOne, "sn-find-by-id-1", now, now, new byte[0]);
        ocspDataProxySessionRemote.storeOcspData(responseA);
        ocspDataProxySessionRemote.storeOcspData(responseB);
        Thread.sleep(1000);

        List<OcspResponseData> foundResponses = ocspDataSessionRemote.findOcspDataBySerialNumber(responseA.getSerialNumber());

        assertEquals(2, foundResponses.size());
        assertEquals(responseA.getSerialNumber(), foundResponses.get(0).getSerialNumber());
        assertEquals(responseA.getSerialNumber(), foundResponses.get(1).getSerialNumber());

        log.trace("<testFindOcspDataBySerialNumber");
    }


    // Local interface methods tested via proxy.

    @Test
    public void testStoreOcspData() throws InterruptedException {
        Long now = System.currentTimeMillis();

        // For either certificateAuthOne or certificateAuthTwo so it can be cleaned at @After
        OcspResponseData response = new OcspResponseData("id-store-ocsp-1", certificateAuthOne, "sn-store-ocsp-1", now, now, new byte[0]);
        ocspDataProxySessionRemote.storeOcspData(response);
        Thread.sleep(1000);

        OcspResponseData found = ocspDataSessionRemote.findOcspDataById(response.getId());

        assertNotNull(found);
        assertEquals(response.getSerialNumber(), found.getSerialNumber());
    }

    @Test
    public void testDeleteOcspDataByCaId() throws InterruptedException {
        Long now = System.currentTimeMillis();

        OcspResponseData response = new OcspResponseData("id-delete-by-ca", certificateAuthOne, "sn-delete-by-ca", now, now, new byte[0]);
        ocspDataProxySessionRemote.storeOcspData(response);
        Thread.sleep(1000);

        OcspResponseData found = ocspDataSessionRemote.findOcspDataById(response.getId());
        assertNotNull(found);

        ocspDataProxySessionRemote.deleteOcspDataByCaId(response.getCaId());
        assertNull(ocspDataSessionRemote.findOcspDataById(response.getId()));
    }

    @Test
    public void testDeleteOcspDataBySerialNumber() throws InterruptedException {
        Long now = System.currentTimeMillis();

        OcspResponseData response = new OcspResponseData("id-delete-by-serial", certificateAuthOne, "sn-delete-by-serial", now, now, new byte[0]);
        ocspDataProxySessionRemote.storeOcspData(response);
        Thread.sleep(1000);

        OcspResponseData found = ocspDataSessionRemote.findOcspDataById(response.getId());
        assertNotNull(found);

        ocspDataProxySessionRemote.deleteOcspDataBySerialNumber(response.getSerialNumber());
        assertNull(ocspDataSessionRemote.findOcspDataById(response.getId()));
    }

    @Test
    public void testDeleteOcspDataByCaIdSerialNumber() throws InterruptedException {
        Long now = System.currentTimeMillis();

        OcspResponseData response = new OcspResponseData("id-delete-by-ca-serial", certificateAuthOne, "sn-delete-by-ca-serial", now, now, new byte[0]);
        ocspDataProxySessionRemote.storeOcspData(response);
        Thread.sleep(1000);

        OcspResponseData found = ocspDataSessionRemote.findOcspDataById(response.getId());
        assertNotNull(found);

        ocspDataProxySessionRemote.deleteOcspDataByCaIdSerialNumber(response.getCaId(), response.getSerialNumber());
        assertNull(ocspDataSessionRemote.findOcspDataById(response.getId()));
    }

    @Test
    public void testDeleteOldOcspDataByCaId() throws InterruptedException {
        log.trace(">testDeleteOldOcspDataByCaId");

        persistMixofExpiredResponses();
        Thread.sleep(2000);

        // Confirm all test data is there.
        assertEquals(5, ocspDataSessionRemote.findOcspDataByCaId(certificateAuthOne).size());
        assertEquals(2, ocspDataSessionRemote.findOcspDataByCaId(certificateAuthTwo).size());

        ocspDataProxySessionRemote.deleteOldOcspDataByCaId(certificateAuthOne);

        // Confirm only latest test data is left for certificateAuthOne
        List<OcspResponseData> remainingResponses = ocspDataSessionRemote.findOcspDataByCaId(certificateAuthOne);
        assertEquals(2, remainingResponses.size());
        assertEquals("test-id-3", remainingResponses.get(0).getId());
        assertEquals("test-id-5", remainingResponses.get(1).getId());

        // Check certificateAuthTwo responses are not deleted.
        assertEquals(2, ocspDataSessionRemote.findOcspDataByCaId(certificateAuthTwo).size());

        log.trace("<testDeleteOldOcspDataByCaId");
    }

    @Test
    public void testDeleteOldOcspData() throws InterruptedException {
        log.trace(">testDeleteOldOcspData");

        persistMixofExpiredResponses();
        Thread.sleep(2000);

        // Confirm all test data is there.
        assertEquals(5, ocspDataSessionRemote.findOcspDataByCaId(certificateAuthOne).size());
        assertEquals(2, ocspDataSessionRemote.findOcspDataByCaId(certificateAuthTwo).size());

        ocspDataProxySessionRemote.deleteOldOcspData();
        List<OcspResponseData> remainingResponses;

        // Confirm only latest test data is left for certificateAuthOne
        remainingResponses = ocspDataSessionRemote.findOcspDataByCaId(certificateAuthOne);
        assertEquals(2, remainingResponses.size());
        assertEquals("test-id-3", remainingResponses.get(0).getId());
        assertEquals("test-id-5", remainingResponses.get(1).getId());

        // Confirm only latest test data is left for certificateAuthOne
        remainingResponses = ocspDataSessionRemote.findOcspDataByCaId(certificateAuthTwo);
        assertEquals(1, ocspDataSessionRemote.findOcspDataByCaId(certificateAuthTwo).size());
        assertEquals("test-id-7", remainingResponses.get(0).getId());

        log.trace("<testDeleteOldOcspData");
    }

    /**
     * Add a mix of expired and active Ocsp Responses.
     */
    private static void persistMixofExpiredResponses() {
        log.trace(">persistMixofExpiredResponses");

        Long now = System.currentTimeMillis();
        Long hourAgo = now - 3600000L;
        Long twoHoursAgo = hourAgo - 3600000L;
        Long future = now + 3600000;

        OcspResponseData certificateAResponseOld1 = new OcspResponseData("test-id-1", certificateAuthOne, "test-sn-1", hourAgo, hourAgo, new byte[0]);
        OcspResponseData certificateAResponseOld2 = new OcspResponseData("test-id-2", certificateAuthOne, "test-sn-1", twoHoursAgo, hourAgo, new byte[0]);
        OcspResponseData certificateAResponseLatest = new OcspResponseData("test-id-3", certificateAuthOne, "test-sn-1", now, future, new byte[0]);

        OcspResponseData certificateBResponseOld = new OcspResponseData("test-id-4", certificateAuthOne, "test-sn-2", hourAgo, future, new byte[0]);
        OcspResponseData certificateBResponseLatest = new OcspResponseData("test-id-5", certificateAuthOne, "test-sn-2", now, hourAgo, new byte[0]);

        OcspResponseData certificateCResponseOld = new OcspResponseData("test-id-6", certificateAuthTwo, "test-sn-3", twoHoursAgo, hourAgo, new byte[0]);
        OcspResponseData certificateCResponseLatest = new OcspResponseData("test-id-7", certificateAuthTwo, "test-sn-3", now, hourAgo, new byte[0]);

        ocspDataProxySessionRemote.storeOcspData(certificateAResponseOld1);
        ocspDataProxySessionRemote.storeOcspData(certificateAResponseOld2);
        ocspDataProxySessionRemote.storeOcspData(certificateAResponseLatest);
        ocspDataProxySessionRemote.storeOcspData(certificateBResponseOld);
        ocspDataProxySessionRemote.storeOcspData(certificateBResponseLatest);
        ocspDataProxySessionRemote.storeOcspData(certificateCResponseOld);
        ocspDataProxySessionRemote.storeOcspData(certificateCResponseLatest);

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
