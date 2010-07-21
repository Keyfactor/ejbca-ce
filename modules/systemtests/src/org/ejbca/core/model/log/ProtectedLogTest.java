package org.ejbca.core.model.log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.EJB;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSSignedData;
import org.ejbca.config.ProtectedLogConfiguration;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.log.LogSessionRemote;
import org.ejbca.core.ejb.log.ProtectedLogSessionRemote;
import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;

public class ProtectedLogTest extends CaTestCase {

    private final static String DEFAULT_CA_NAME = "TEST";
    private final static String LOGMESSAGE = "Logmessage ";
    private final static String ERROR_LASTACTION = "Last actions should not have generated an error.";
    private final static String ERROR_NONEMPTY = "The protected log was not empty.";
    private final static String ERROR_MISSINGROW = "Did not detect missing rows.";
    private final static String ERROR_FROZENLOG = "Did not detect frozen log.";
    private final static String ERROR_UNPROTECTED = "The protected log was not unprotected.";
    private final static String ERROR_NOEXPORT = "No export file was written.";
    private final static String ERROR_BADEXPORT = "Exported log does not contain any log-data";

    private static final Logger log = Logger.getLogger(ProtectedLogTest.class);
    private final Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);

    @EJB
    private ConfigurationSessionRemote configurationSessionRemote;
    
    @EJB
    private LogSessionRemote logSession;
    
    @EJB
    private ProtectedLogSessionRemote protectedLogSession;

    /**
     * Creates a new TestProtectedLog object.
     * 
     * @param name
     *            name
     */
    public ProtectedLogTest(String name) {
        super(name);
        assertTrue("Could not create TestCA.", createTestCA());
    }

    public void setUp() throws Exception {
        log.trace(">setUp()");
        // Stop services
        protectedLogSession.stopServices();
        // Clear protected log
        protectedLogSession.removeAllUntil(System.currentTimeMillis());
        protectedLogSession.removeAllExports(true);
        // Make sure tempfile is removed
        ProtectedLogTestAction.removeFileInTempDir();
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_USESCRIPTACTION, "false");
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_USEMAILACTION, "false");
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_USESHUTDOWNACTION, "false");
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_USETESTACTION, "true");
        log.trace("<setUp()");
    }

    public void tearDown() throws Exception {
        configurationSessionRemote.restoreConfiguration();
        // Clear protected log
        protectedLogSession.removeAllUntil(System.currentTimeMillis() + 60 * 1000);
        protectedLogSession.removeAllExports(true);
        // Restore log devices
        logSession.restoreTestDevice();
        // Start servies
        protectedLogSession.startServices();
        ProtectedLogTestAction.removeFileInTempDir();
    }

    /**
     * Test single node Verifies protected log when everything is ok Fails when
     * event is removed Tries emergency recovery
     */
    public void test01() throws Exception {
        // Setup a protected log device
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_TOKENREFTYPE, ProtectedLogConfiguration.CONFIG_TOKENREFTYPE_CANAME);
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_TOKENREF, DEFAULT_CA_NAME);
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_SEARCHWINDOW, "1");
        logSession.setTestDevice(ProtectedLogDeviceFactory.class, ProtectedLogDevice.DEFAULT_DEVICE_NAME);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        // Write an logevent and make sure it complains about an empty log
        int messageCounter = 0;
        logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_SERVICES, new Date(), null, null,
                LogConstants.EVENT_INFO_STARTING, LOGMESSAGE + messageCounter++, null);
        assertEquals(ERROR_NONEMPTY, IProtectedLogAction.CAUSE_EMPTY_LOG, ProtectedLogTestAction.getLastActionCause());
        // Write another and make sure there are no error message
        logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(), null, null,
                LogConstants.EVENT_INFO_UNKNOWN, LOGMESSAGE + messageCounter++, null);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        // Test if log-freeze is detected
        protectedLogSession.verifyEntireLog(ProtectedLogConstants.ACTION_TEST, -1);
        assertEquals(ERROR_FROZENLOG, IProtectedLogAction.CAUSE_FROZEN, ProtectedLogTestAction.getLastActionCause());
        protectedLogSession.verifyEntireLog(ProtectedLogConstants.ACTION_TEST, 3600 * 1000);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        // Test if removed logevents are detected
        long testTime1 = System.currentTimeMillis();
        protectedLogSession.removeAllUntil(testTime1);
        Thread.sleep(1100); // Default interval to search for its own event in
                            // database is 1 second.
        logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(), null, null,
                LogConstants.EVENT_INFO_UNKNOWN, LOGMESSAGE + messageCounter++, null);
        assertEquals(ERROR_MISSINGROW, IProtectedLogAction.CAUSE_MISSING_LOGROW, ProtectedLogTestAction.getLastActionCause());
        protectedLogSession.verifyEntireLog(ProtectedLogConstants.ACTION_TEST, 3600 * 1000);
        assertEquals(ERROR_MISSINGROW, IProtectedLogAction.CAUSE_MISSING_LOGROW, ProtectedLogTestAction.getLastActionCause());
        // Recover
        protectedLogSession.resetEntireLog(false);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        protectedLogSession.verifyEntireLog(ProtectedLogConstants.ACTION_TEST, 3600 * 1000);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
    }

    /**
     * Test startup behavior Start and stop node with none-token Start node with
     * CAToken and sign unprotected chain.
     */
    public void test02() throws Exception {
        // Setup a protected log device
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_TOKENREFTYPE, ProtectedLogConfiguration.CONFIG_TOKENREFTYPE_NONE);
        logSession.setTestDevice(ProtectedLogDeviceFactory.class, ProtectedLogDevice.DEFAULT_DEVICE_NAME);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        // Write an logevent and make sure it complains about an empty log
        int messageCounter = 0;
        logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(), null, null,
                LogConstants.EVENT_INFO_UNKNOWN, LOGMESSAGE + messageCounter++, null);
        assertEquals(ERROR_NONEMPTY, IProtectedLogAction.CAUSE_EMPTY_LOG, ProtectedLogTestAction.getLastActionCause());
        logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_LOG, new Date(), null, null,
                LogConstants.EVENT_SYSTEM_STOPPED_LOGGING, "Terminating log session for this node.", null);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        // Start new chain with CAName-token
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_TOKENREFTYPE, ProtectedLogConfiguration.CONFIG_TOKENREFTYPE_CANAME);
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_TOKENREF, DEFAULT_CA_NAME);
        logSession.setTestDevice(ProtectedLogDeviceFactory.class, ProtectedLogDevice.DEFAULT_DEVICE_NAME);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(), null, null,
                LogConstants.EVENT_INFO_UNKNOWN, LOGMESSAGE + messageCounter++, null);
        assertEquals(ERROR_UNPROTECTED, IProtectedLogAction.CAUSE_EMPTY_LOG, ProtectedLogTestAction.getLastActionCause());
        protectedLogSession.verifyEntireLog(ProtectedLogConstants.ACTION_TEST, 3600 * 1000);
        assertEquals(ERROR_UNPROTECTED, IProtectedLogAction.CAUSE_UNVERIFYABLE_CHAIN, ProtectedLogTestAction.getLastActionCause());
        // Sign unsigned chain so it can be linked in
        protectedLogSession.signAllUnsignedChains(true);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        Thread.sleep(1100); // By default it takes 1 second between searches new
                            // events from other nodes..
        // And that event will be set 10 seconds in the future so we have to
        // wait 10 more seconds or "cheat"
        logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(new Date().getTime() + 10 * 1000), null,
                null, LogConstants.EVENT_INFO_UNKNOWN, LOGMESSAGE + messageCounter++, null);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        protectedLogSession.verifyEntireLog(ProtectedLogConstants.ACTION_TEST, 3600 * 1000);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        // Now try to remove the first chain and see if it will be detected
        protectedLogSession.removeNodeChain(protectedLogSession.findOldestProtectedLogEventRow().getNodeGUID());
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        protectedLogSession.verifyEntireLog(ProtectedLogConstants.ACTION_TEST, 3600 * 1000);
        assertEquals(ERROR_UNPROTECTED, IProtectedLogAction.CAUSE_MISSING_LOGROW, ProtectedLogTestAction.getLastActionCause());
    }

    /**
     * Test export handler Exports log with CMS export handler and verifies that
     * content contains log. Exports next part of log and verify that there is
     * no overlap
     */
    public void test03() throws Exception {
        final String logPrefix = "uniquelogprefix_";
        boolean wasCMSDisabled = false;
        // Remove any exported file
        File dir = new File(ProtectedLogTestAction.getTempDir());
        File[] files = dir.listFiles();
        for (int i = 0; i < files.length; i++) {
            if (files[i].getName().indexOf(logPrefix) != -1) {
                files[i].delete();
            }
        }
        // Setup a protected log device
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_TOKENREFTYPE, ProtectedLogConfiguration.CONFIG_TOKENREFTYPE_CANAME);
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_TOKENREF, DEFAULT_CA_NAME);
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_CMS_EXPORTPATH, ProtectedLogTestAction.getTempDir() + logPrefix);
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_CMS_CANAME, DEFAULT_CA_NAME);
        logSession.setTestDevice(ProtectedLogDeviceFactory.class, ProtectedLogDevice.DEFAULT_DEVICE_NAME);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        int messageCounter = 0;
        logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(), null, null,
                LogConstants.EVENT_INFO_UNKNOWN, LOGMESSAGE + messageCounter++, null);
        assertEquals(ERROR_NONEMPTY, IProtectedLogAction.CAUSE_EMPTY_LOG, ProtectedLogTestAction.getLastActionCause());
        // Activate CMS service
        X509CAInfo x509cainfo = (X509CAInfo) caAdminSessionRemote.getCAInfo(internalAdmin, DEFAULT_CA_NAME);
        assertTrue("The test expects the CA \"" + DEFAULT_CA_NAME + "\" to exist.", x509cainfo != null);
        CmsCAServiceInfo cmscainfo = null;
        Collection extendedCAServiceInfos = x509cainfo.getExtendedCAServiceInfos();
        if (extendedCAServiceInfos == null) {
            wasCMSDisabled = true;
        } else {
            Iterator iter = extendedCAServiceInfos.iterator();
            while (iter.hasNext()) {
                ExtendedCAServiceInfo serviceinfo = (ExtendedCAServiceInfo) iter.next();
                if (serviceinfo instanceof CmsCAServiceInfo) {
                    cmscainfo = (CmsCAServiceInfo) serviceinfo;
                    if (cmscainfo.getStatus() == CmsCAServiceInfo.STATUS_INACTIVE) {
                        wasCMSDisabled = true;
                    }
                }
            }
        }
        if (wasCMSDisabled) {
            ArrayList extendedcaserviceinfos = new ArrayList();
            extendedcaserviceinfos.add(new OCSPCAServiceInfo(OCSPCAServiceInfo.STATUS_ACTIVE));
            extendedcaserviceinfos.add(new XKMSCAServiceInfo(XKMSCAServiceInfo.STATUS_ACTIVE, false));
            extendedcaserviceinfos.add(new CmsCAServiceInfo(CmsCAServiceInfo.STATUS_ACTIVE, "CN=CMSCertificate, " + x509cainfo.getSubjectDN(), "",
                    ((SoftCATokenInfo) x509cainfo.getCATokenInfo()).getSignKeySpec(), ((SoftCATokenInfo) x509cainfo.getCATokenInfo()).getSignKeyAlgorithm()));
            x509cainfo.setExtendedCAServiceInfos(extendedcaserviceinfos);
            caAdminSessionRemote.editCA(internalAdmin, x509cainfo);
        }
        try {
            // Write an logevent and make sure it complains about an empty log
            while (messageCounter < 100) {
                logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(), null, null,
                        LogConstants.EVENT_INFO_UNKNOWN, LOGMESSAGE + messageCounter++, null);
            }
            assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
            // Do export
            protectedLogSession.exportLog(new ProtectedLogCMSExportHandler(), ProtectedLogConstants.ACTION_TEST, "SHA-256", false, 0);
            assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
            // See if any file was exported
            File file = null;
            dir = new File(ProtectedLogTestAction.getTempDir());
            files = dir.listFiles();
            for (int i = 0; i < files.length; i++) {
                if (files[i].getName().indexOf(logPrefix) != -1) {
                    file = files[i];
                    break;
                }
            }
            assertTrue(ERROR_NOEXPORT, file != null);
            CMSSignedData cmsSignedData = new CMSSignedData(new FileInputStream(file));
            file.delete();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            cmsSignedData.getSignedContent().write(baos);
            assertTrue(ERROR_BADEXPORT, baos.toString().indexOf(LOGMESSAGE + (messageCounter - 1)) != -1);
            // Export another 100 rows and make sure they don't overlap
            // Write an logevent and make sure it complains about an empty log
            while (messageCounter < 100 + 100) {
                logSession.log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(), null, null,
                        LogConstants.EVENT_INFO_UNKNOWN, LOGMESSAGE + messageCounter++, null);
            }
            assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
            // Do export
            protectedLogSession.exportLog(new ProtectedLogCMSExportHandler(), ProtectedLogConstants.ACTION_TEST, "SHA-256", false, 0);
            assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
            // See if any file was exported
            file = null;
            dir = new File(ProtectedLogTestAction.getTempDir());
            files = dir.listFiles();
            for (int i = 0; i < files.length; i++) {
                if (files[i].getName().indexOf(logPrefix) != -1) {
                    file = files[i];
                    break;
                }
            }
            assertTrue(ERROR_NOEXPORT, file != null);
            cmsSignedData = new CMSSignedData(new FileInputStream(file));
            file.delete();
            baos = new ByteArrayOutputStream();
            cmsSignedData.getSignedContent().write(baos);
            assertTrue(ERROR_BADEXPORT, baos.toString().indexOf(LOGMESSAGE + (messageCounter - 100)) != -1);
            assertTrue(ERROR_BADEXPORT, baos.toString().indexOf(LOGMESSAGE + (messageCounter - 101)) == -1);
        } finally {
            // Deactivate CMS service if needed
            if (wasCMSDisabled) {
                x509cainfo = (X509CAInfo) caAdminSessionRemote.getCAInfo(internalAdmin, DEFAULT_CA_NAME);
                // CmsCAServiceInfo cmscainfo = null;
                ArrayList extendedcaserviceinfos = new ArrayList();
                extendedcaserviceinfos.add(new OCSPCAServiceInfo(OCSPCAServiceInfo.STATUS_ACTIVE));
                extendedcaserviceinfos.add(new XKMSCAServiceInfo(XKMSCAServiceInfo.STATUS_ACTIVE, false));
                extendedcaserviceinfos
                        .add(new CmsCAServiceInfo(CmsCAServiceInfo.STATUS_INACTIVE, "CN=CMSCertificate, " + x509cainfo.getSubjectDN(), "",
                                ((SoftCATokenInfo) x509cainfo.getCATokenInfo()).getSignKeySpec(), ((SoftCATokenInfo) x509cainfo.getCATokenInfo())
                                        .getSignKeyAlgorithm()));
                x509cainfo.setExtendedCAServiceInfos(extendedcaserviceinfos);
                caAdminSessionRemote.editCA(internalAdmin, x509cainfo);
            }
        }
    }

    /**
     * Test that a log-events isn't rolled back when the surrounding transaction
     * is.
     * 
     * @throws Exception
     */
    public void test04() throws Exception {
        long now = System.currentTimeMillis();
        // Setup a protected log device
        configurationSessionRemote.updateProperty(ProtectedLogConfiguration.CONFIG_TOKENREFTYPE, ProtectedLogConfiguration.CONFIG_TOKENREFTYPE_NONE);
        logSession.setTestDevice(ProtectedLogDeviceFactory.class, ProtectedLogDevice.DEFAULT_DEVICE_NAME);
        logSession.setTestDeviceOnLogSession(ProtectedLogDeviceFactory.class, ProtectedLogDevice.DEFAULT_DEVICE_NAME);
        assertTrue(ERROR_LASTACTION, ProtectedLogTestAction.getLastActionCause() == null);
        try {
            logSession.testRollbackInternal(now);
        } catch (Exception e) {
        }
        // TODO: The following test fails on Hypersonic the second time for some
        // reason...
        assertEquals(ERROR_NONEMPTY, IProtectedLogAction.CAUSE_EMPTY_LOG, ProtectedLogTestAction.getLastActionCause());
        // Verify that event written at time "now" still exists
        assertTrue("The log event has been rolled back and cannot be found any more..", protectedLogSession
                .existsAnyProtectedLogEventByTime(now));
        logSession.restoreTestDeviceOnLogSession();
    }

    public void test99RemoveTestCA() throws Exception {
        removeTestCA();
    }
}
