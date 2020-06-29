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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationProxySessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ocsp.OcspDataSessionRemote;
import org.ejbca.core.ejb.ocsp.OcspResponseCleanupSession;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.ejb.ScheduleExpression;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;


/**
 * @version $Id$
 */
public class OcspResponseCleanupSessionBeanTest {
    private static final Logger log = Logger.getLogger(OcspResponseCleanupSessionBeanTest.class);
    private static final EjbRemoteHelper ejbRemoteHelper = EjbRemoteHelper.INSTANCE;

    private static final OcspCleanupProxySessionRemote ocspCleanup = ejbRemoteHelper.getRemoteSession(OcspCleanupProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final OcspDataProxySessionRemote ocspDataProxySessionRemote = ejbRemoteHelper.getRemoteSession(OcspDataProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final GlobalConfigurationProxySessionRemote globalConfigSession = ejbRemoteHelper.getRemoteSession(GlobalConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final OcspDataSessionRemote ocspDataSessionRemote = ejbRemoteHelper.getRemoteSession(OcspDataSessionRemote.class);

    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(OcspResponseCleanupSessionBeanTest.class.getName());
    private static final Integer certificateAuth = 123456789;

    @Before
    public void stopAllCleanupJobs() {
        log.trace(">stopAllCleanupJobs");
        ocspCleanup.stop();
    }

    @After
    public void restoreCleanupJobs() {
        log.trace(">restoreCleanupJobs");
        ocspCleanup.start();
        removeOcspResponses();
    }

    @Test
    public void testOldResponsesDeletedByJob() throws InterruptedException {
        log.trace(">testOldResponsesDeletedByJob");

        // Persists OCSP Response data.
        persistOcspResponses();
        Thread.sleep(2000);

        // Assert starting conditions.
        List<OcspResponseData> responses = ocspDataSessionRemote.findOcspDataByCaId(certificateAuth);
        assertEquals(5, responses.size());

        // Start the job and stop it after it runs.
        // Every 5 seconds.
        ocspCleanup.start("*", "*", "*/5");
        Thread.sleep(TimeUnit.SECONDS.toMillis(6));
        ocspCleanup.stop();

        // Assert only latest responses are left.
        responses = ocspDataSessionRemote.findOcspDataByCaId(certificateAuth);
        assertEquals(2, responses.size());

        List<String> responseIds = responses.stream().map(r -> r.getId()).collect(Collectors.toList());
        assertTrue("Response id (test-id-3) should be found", responseIds.contains("test-id-3"));
        assertTrue("Response id (test-id-5) should be found", responseIds.contains("test-id-5"));

        log.trace(">testOldResponsesDeletedByJob");
    }

    @Test
    public void testTimersAreStartedAndStoppedCorrectly() {
        log.trace(">testTimersAreStartedAndStoppedCorrectly");

        assertFalse(ocspCleanup.hasTimers());

        // 23:59:59
        ocspCleanup.start("23", "59", "59");
        assertTrue(ocspCleanup.hasTimers());

        ocspCleanup.stop();
        assertFalse(ocspCleanup.hasTimers());

        log.trace(">testTimersAreStartedAndStoppedCorrectly");
    }

    @Test
    public void testGlobalConfigurationSettingsAreUsed() throws AuthorizationDeniedException, InterruptedException {
        // Change the cleanup settings in GC
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final String prevUnit = gc.getOcspCleanupScheduleUnit();
        final String prevSchedule = gc.getOcspCleanupSchedule();
        final boolean prevUse = gc.getOcspCleanupUse();

        gc.setOcspCleanupScheduleUnit("MINUTES");
        gc.setOcspCleanupUse(true);
        gc.setOcspCleanupSchedule("1");
        globalConfigSession.saveConfiguration(alwaysAllowToken, gc);

        // Persist data
        persistOcspResponses();
        Thread.sleep(2000);

        // Run the job
        ocspCleanup.start();
        Thread.sleep(60000);
        ocspCleanup.stop();

        // Assert only latest responses are left.
        assertEquals(2, ocspDataSessionRemote.findOcspDataByCaId(certificateAuth).size());

        gc.setOcspCleanupScheduleUnit(prevUnit);
        gc.setOcspCleanupSchedule(prevSchedule);
        gc.setOcspCleanupUse(prevUse);
        globalConfigSession.saveConfiguration(alwaysAllowToken, gc);
    }

    @Test
    public void testConvertToScheduleReturnsDefaultForInvalidValues() {
        // In this case: less than a minute.
        ScheduleExpression expected = new ScheduleExpression().second("0").minute("0").hour("*");
        ScheduleExpression result = OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.SECONDS.toMillis(15));

        assertEqualSchedules(expected, result);
    }

    @Test
    public void testConvertToScheduleDailySchedule() {
        ScheduleExpression expected = new ScheduleExpression().second("0").minute("0").hour("0").dayOfMonth("1,5,10,15,20,25,30");

        assertEqualSchedules(expected, OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.HOURS.toMillis(120)));
        assertEqualSchedules(expected, OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.HOURS.toMillis(134)));
    }

    @Test
    public void testConvertToScheduleHourlySchedule() {
        ScheduleExpression expected = new ScheduleExpression().second("0").minute("0").hour("*/5");

        assertEqualSchedules(expected, OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.MINUTES.toMillis(300)));
        assertEqualSchedules(expected, OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.MINUTES.toMillis(330)));
    }

    @Test
    public void testConvertToScheduleMinutesSchedule() {
        ScheduleExpression expected = new ScheduleExpression().second("0").minute("*/5").hour("*");

        assertEqualSchedules(expected, OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.SECONDS.toMillis(300)));
        assertEqualSchedules(expected, OcspResponseCleanupSession.convertToScheduleFromMS(TimeUnit.SECONDS.toMillis(330)));
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

    private void assertEqualSchedules(ScheduleExpression expected, ScheduleExpression result) {
        assertEquals("Seconds should match", expected.getSecond(), result.getSecond());
        assertEquals("Minutes should match", expected.getMinute(), result.getMinute());
        assertEquals("Hours should match", expected.getHour(), result.getHour());
        assertEquals("Days should match", expected.getDayOfMonth(), result.getDayOfMonth());
        assertEquals("Years should match", expected.getYear(), result.getYear());
    }
}
