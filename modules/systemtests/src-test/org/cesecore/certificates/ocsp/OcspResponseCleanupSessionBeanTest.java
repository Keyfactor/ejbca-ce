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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.log4j.Logger;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.StartupSingletonBean;
import org.ejbca.core.ejb.ocsp.OcspDataSessionRemote;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.ejb.ScheduleExpression;
import java.util.List;
import java.util.concurrent.TimeUnit;


/**
 * @version $Id$
 */
public class OcspResponseCleanupSessionBeanTest {
    private static final Logger log = Logger.getLogger(OcspResponseCleanupSessionBeanTest.class);
    private final static EjbRemoteHelper ejbRemoteHelper = EjbRemoteHelper.INSTANCE;

    private final static OcspCleanupProxySessionRemote ocspCleanup = ejbRemoteHelper.getRemoteSession(OcspCleanupProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final static OcspDataProxySessionRemote ocspDataProxySessionRemote = ejbRemoteHelper.getRemoteSession(OcspDataProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final static OcspDataSessionRemote ocspDataSessionRemote = ejbRemoteHelper.getRemoteSession(OcspDataSessionRemote.class);

    private final static Integer certificateAuth = 123456789;

    @Before
    public void stopAllCleanupJobs() {
        log.trace(">stopAllCleanupJobs");
        ocspCleanup.stop(StartupSingletonBean.class.getName());
    }

    @After
    public void restoreCleanupJobs() {
        log.trace(">restoreCleanupJobs");
        ocspCleanup.start(StartupSingletonBean.class.getName());
        removeOcspResponses();
    }

    @Test
    public void testOldResponsesDeletedByJob() throws InterruptedException {
        log.trace(">testOldResponsesDeletedByJob");

        final ScheduleExpression schedule = new ScheduleExpression();
        schedule.second("*/5").minute("*").hour("*");
        final String callerName = OcspResponseCleanupSessionBeanTest.class.getName();

        // Persists OCSP Response data.
        persistOcspResponses();
        Thread.sleep(2000);

        // Assert starting conditions.
        List<OcspResponseData> responses = ocspDataSessionRemote.findOcspDataByCaId(certificateAuth);
        assertEquals(5, responses.size());

        // Start the job and stop it after it runs.
        ocspCleanup.start(callerName, schedule);
        Thread.sleep(TimeUnit.SECONDS.toMillis(6));
        ocspCleanup.stop(callerName);

        // Assert only latest responses are left.
        responses = ocspDataSessionRemote.findOcspDataByCaId(certificateAuth);
        assertEquals(2, responses.size());
        assertEquals("test-id-3", responses.get(0).getId());
        assertEquals("test-id-5", responses.get(1).getId());

        log.trace(">testOldResponsesDeletedByJob");
    }

    @Test
    public void testTimersAreStartedAndStoppedCorrectly() {
        log.trace(">testTimersAreStartedAndStoppedCorrectly");
        ScheduleExpression schedule = new ScheduleExpression();
        schedule.second("59").minute("59").hour("23").year(2999);

        final String callerName = "TEST01";
        assertFalse(ocspCleanup.hasTimers(callerName));

        ocspCleanup.start(callerName, schedule);
        assertTrue(ocspCleanup.hasTimers(callerName));

        ocspCleanup.stop(callerName);
        assertFalse(ocspCleanup.hasTimers(callerName));

        log.trace(">testTimersAreStartedAndStoppedCorrectly");
    }

    private void persistOcspResponses() {
        log.trace(">persistOcspResponses");
        long now = System.currentTimeMillis();
        long hourAgo = now - TimeUnit.HOURS.toMillis(1);
        long twoHoursAgo = hourAgo - TimeUnit.HOURS.toMillis(1);
        long future = now + TimeUnit.HOURS.toMillis(1);

        OcspResponseData responseA = new OcspResponseData("test-id-1", certificateAuth, "test-sn-1", hourAgo, hourAgo, new byte[0]);
        OcspResponseData responseB = new OcspResponseData("test-id-2", certificateAuth, "test-sn-1", twoHoursAgo, hourAgo, new byte[0]);
        OcspResponseData responseC = new OcspResponseData("test-id-3", certificateAuth, "test-sn-1", now, future, new byte[0]);

        OcspResponseData responseD = new OcspResponseData("test-id-4", certificateAuth, "test-sn-2", hourAgo, future, new byte[0]);
        OcspResponseData responseE = new OcspResponseData("test-id-5", certificateAuth, "test-sn-2", now, hourAgo, new byte[0]);

        ocspDataProxySessionRemote.storeOcspData(responseA);
        ocspDataProxySessionRemote.storeOcspData(responseB);
        ocspDataProxySessionRemote.storeOcspData(responseC);
        ocspDataProxySessionRemote.storeOcspData(responseD);
        ocspDataProxySessionRemote.storeOcspData(responseE);
        log.trace("<persistOcspResponses");
    }

    private static void removeOcspResponses() {
        log.trace(">removeOcspResponses");
        ocspDataProxySessionRemote.deleteOcspDataByCaId(certificateAuth);
        log.trace("<removeOcspResponses");
    }
}
