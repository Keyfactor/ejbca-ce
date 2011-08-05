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
package org.cesecore.audit.log;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;
import static junit.framework.Assert.fail;
import static org.cesecore.util.QueryCriteria.where;

import java.io.File;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.time.StopWatch;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.SecurityEventsBase;
import org.cesecore.audit.audit.AuditLogReportElem;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.SecurityEventsAuditorSession;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.CryptoProviderTools;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Secure audit logs logger functional tests.
 * 
 * Based on cesecore version:
 *      SecurityEventsLoggerSessionBeanTest.java 920 2011-07-01 11:27:04Z filiper
 *      
 * Tests for queued devices (not included in EJBCA) have been culled.
 * 
 * @version $Id$
 * 
 */
public class SecurityEventsLoggerSessionBeanTest extends SecurityEventsBase {

    private static final Logger log = Logger.getLogger(SecurityEventsLoggerSessionBeanTest.class);
    private final SecurityEventsLoggerSession securityEventsLogger = JndiHelper.getRemoteSession(SecurityEventsLoggerSessionRemote.class);
    private final SecurityEventsAuditorSession securityEventsAuditor = JndiHelper.getRemoteSession(SecurityEventsAuditorSessionRemote.class);
    private final TxFailureLoggerOperationSessionRemote txFailure = JndiHelper.getRemoteSession(TxFailureLoggerOperationSessionRemote.class);

    @BeforeClass
    public static void setUpCryptoProvider() {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void test01SecureLogWithoutAdditionalDetails() {
        log.trace(">test01SecureLogWithoutAdditionalDetails");
        securityEventsLogger.log(EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE, "authToken");
        log.trace("<test01SecureLogWithoutAdditionalDetails");
    }

    @Test
    public void test02logAppCustomEventTypes() throws Exception {
        log.trace(">test02logAppCustomEventTypes");
        securityEventsLogger.log(ExampleEnumEventTypes.NEW_EVENT_TYPE, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE,
                "authToken");
        securityEventsLogger.log(ExampleClassEventTypes.NEW_EVENT_TYPE_CLASS, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE,
                "authToken");
        for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> lastSignedLogs = securityEventsAuditor.selectAuditLogs(
                    roleMgmgToken,
                    1,
                    10,
                    where().eq(AuditLogEntry.FIELD_EVENTTYPE, ExampleEnumEventTypes.NEW_EVENT_TYPE.toString()).or()
                            .eq(AuditLogEntry.FIELD_EVENTTYPE, ExampleClassEventTypes.NEW_EVENT_TYPE_CLASS.toString()), logDeviceId);
            assertEquals(2, lastSignedLogs.size());
            for(AuditLogEntry ae: lastSignedLogs) {
                assertTrue(ae.getEventTypeValue().equals(ExampleEnumEventTypes.NEW_EVENT_TYPE) || 
                        ae.getEventTypeValue().equals(ExampleClassEventTypes.NEW_EVENT_TYPE_CLASS));
            }
        }

        log.trace("<test02logAppCustomEventTypes");
    }

    @Test
    public void test03SecurelogWithAdditionalDetails() {
        log.trace(">test02SecurelogWithAdditionalDetails");
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        final Map<String, String> innerDetails = new LinkedHashMap<String, String>();
        innerDetails.put("extra", "bar");
        details.put("foo", innerDetails);
        securityEventsLogger.log(EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE, "authToken", "0",
                "0", "someentityname", details);
        log.trace("<test02SecurelogWithAdditionalDetails");
    }

    @Test
    public void test04SecureMultipleLog() throws Exception {
        log.trace(">test03SecureMultipleLog");
        final int THREADS = 50;
        final int WORKERS = 400;
        final int TIMEOUT_MS = 30000;
        final ThreadPoolExecutor workers = (ThreadPoolExecutor) Executors.newFixedThreadPool(THREADS);
        final StopWatch time = new StopWatch();

        time.start();
        for (int i = 0; i < WORKERS; i++) {
            workers.execute(new Runnable() {
                @Override
                public void run() {
                    securityEventsLogger.log(EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE,
                            "test03SecureMultipleLogAuthToken");
                }
            });
        }
        while (workers.getCompletedTaskCount() < WORKERS && time.getTime() < TIMEOUT_MS) {
            Thread.sleep(250);
        }
        time.stop();
        final int completedTaskCount = Long.valueOf(workers.getCompletedTaskCount()).intValue();
        log.info("securityEventsLogger.log: " + completedTaskCount + " completed in " + time.toString() + " using " + THREADS + " threads.");
        workers.shutdown();

        for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            final AuditLogValidationReport report = securityEventsAuditor.verifyLogsIntegrity(roleMgmgToken, new Date(), logDeviceId);
            assertNotNull(report);
            final StringBuilder strBuilder = new StringBuilder();
            for (final AuditLogReportElem error : report.errors()) {
                strBuilder.append(String.format("invalid sequence: %d %d\n", error.getFirst(), error.getSecond()));
                for (final String reason : error.getReasons()) {
                    strBuilder.append(String.format("Reason: %s\n", reason));
                }
            }
            assertTrue("validation report: " + strBuilder.toString(), (report.warnings().size() == 1 || report.warnings().size() == 0)
                    && report.errors().size() == 0);
        }
        log.trace("<test03SecureMultipleLog");
    }

    @Test
    public void test05ExportGeneratedLogs() throws Exception {
        log.trace(">test04ExportGeneratedLogs");
        final CryptoToken cryptoToken = createTokenWithKeyPair();
        for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            final String exportFilename = securityEventsAuditor.exportAuditLogs(roleMgmgToken, cryptoToken, new Date(), true, keyAlias,
                    keyPairSignAlgorithm, logDeviceId).getExportedFile();
            assertExportAndSignatureExists(exportFilename);
        }
        log.trace("<test04ExportGeneratedLogs");
    }

    @Test
    // (expected = Exception.class)
    public void test06TxFailure() throws Exception {
        log.trace(">test05TxFailure");
        try {
            txFailure.willLaunchExceptionAfterLog();
            fail("No exception was thrown..");
        } catch (final Exception e) {
            // Expected
        }
        for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> list = securityEventsAuditor.selectAuditLogs(roleMgmgToken, 1, 10,
                    where().like(AuditLogEntry.FIELD_AUTHENTICATION_TOKEN, "TxFailureUser"), logDeviceId);
            assertEquals("List size is:" + list.size(), 1, list.size());
        }
        log.trace("<test05TxFailure");
    }

   

    @AfterClass
    public static void setDown() {
        CryptoProviderTools.removeBCProvider();
    }

    private void assertExportAndSignatureExists(final String exportFilename) {
        final File exportFile = new File(exportFilename);
        assertTrue("file does not exist, " + exportFile.getAbsolutePath(), exportFile.exists());
        assertTrue("file length is not > 0, " + exportFile.getAbsolutePath(), exportFile.length() > 0);
        assertTrue("file can not be deleted, " + exportFile.getAbsolutePath(), exportFile.delete());
        final File signatureFile = new File(String.format("%s.sig", FilenameUtils.removeExtension(exportFile.getAbsolutePath())));
        assertTrue("signatureFile does not exist, " + signatureFile.getAbsolutePath(), signatureFile.exists());
        assertTrue("signatureFile length is not > 0, " + signatureFile.getAbsolutePath(), signatureFile.length() > 0);
        assertTrue("signatureFile can not be deleted, " + signatureFile.getAbsolutePath(), signatureFile.delete());
    }
}
