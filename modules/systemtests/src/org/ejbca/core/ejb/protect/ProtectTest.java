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

package org.ejbca.core.ejb.protect;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.config.ProtectConfiguration;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.protect.TableVerifyResult;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;

/**
 * Tests the log modules entity and session beans.
 *
 * @version $Id$
 */
public class ProtectTest extends TestCase {
    private static Logger log = Logger.getLogger(ProtectTest.class);

    private static ArrayList<LogEntry> entrys = null;

    private final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    private TableProtectSessionRemoteejb3 tableProtectSession = InterfaceCache.getTableProtectSession();
    private ConfigurationSessionRemote configurationSessionRemote = InterfaceCache.getConfigurationSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();

    /**
     * Creates a new TestLog object.
     *
     * @param name name
     */
    public ProtectTest(String name) {
        super(name);
        CryptoProviderTools.installBCProvider();
    }

    public void setUp() throws Exception {
        log.trace(">setUp()");
        configurationSessionRemote.updateProperty(ProtectConfiguration.CONFIG_PROTECTIONENABLED, "true");
        if (entrys == null) {
        	createLogEntrys();
        }
        log.trace("<setUp()");
    }

    public void tearDown() throws Exception {
    	configurationSessionRemote.restoreConfiguration();
    }

    private void createLogEntrys() {
    	entrys = new ArrayList<LogEntry>();
        Random rand = new Random();
        LogEntry le1 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogConstants.MODULE_CA, new Date(2), "foo", "123456", LogConstants.EVENT_ERROR_ADDEDENDENTITY, "foo comment 1");
        LogEntry le2 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogConstants.MODULE_CA, new Date(3), "foo", "123456", LogConstants.EVENT_ERROR_ADDEDENDENTITY, "foo comment 2");
        LogEntry le3 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogConstants.MODULE_CA, new Date(4), "foo", "123456", LogConstants.EVENT_ERROR_ADDEDENDENTITY, "foo comment 3");
        LogEntry le4 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogConstants.MODULE_CA, new Date(5), "foo", "123456", LogConstants.EVENT_ERROR_ADDEDENDENTITY, "foo comment 4");
        LogEntry le5 = new LogEntry(rand.nextInt(),Admin.TYPE_INTERNALUSER, "12345", -1, LogConstants.MODULE_CA, new Date(6), "foo", "123456", LogConstants.EVENT_ERROR_ADDEDENDENTITY, "foo comment 5");
        entrys.add(le1);
        entrys.add(le2);
        entrys.add(le3);
        entrys.add(le4);
        entrys.add(le5);
    }

    /**
     * tests adding protection to a log event.
     *
     * @throws Exception error
     */
    public void test01ProtectLogEntry() throws Exception {
        log.trace(">test01ProtectLogEntry()");
        Iterator<LogEntry> iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le = iter.next();
            tableProtectSession.protect(le);        	
        }
        log.trace("<test01ProtectLogEntry()");
    }

    /**
     * tests verify protection for a log event
     *
     * @throws Exception error
     */
    public void test02VerifyLogEntry() throws Exception {
        log.trace(">test02VerifyLogEntry()");
        Iterator<LogEntry> iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le = iter.next();
            TableVerifyResult res = tableProtectSession.verify(le);
            assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);
        }
        LogEntry le = (LogEntry)entrys.get(2);
        LogEntry le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), le.getTime(), le.getUsername(), le.getCertificateSNR(), le.getEvent(), "modified");
        entrys.set(2, le1);
        iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le2 = (LogEntry)iter.next();
            TableVerifyResult res = tableProtectSession.verify(le2);
            if (le2.getId() == le.getId()) {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);            	
            } else {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);            	            	
            }
        }
        le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), le.getTime(), le.getUsername(), le.getCertificateSNR(), le.getEvent(), le.getComment());
        entrys.set(2, le1);
        le = (LogEntry)entrys.get(3);
        le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), le.getTime(), le.getUsername(), le.getCertificateSNR(), LogConstants.EVENT_INFO_CAEDITED, le.getComment());
        entrys.set(3, le1);
        iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le2 = (LogEntry)iter.next();
            TableVerifyResult res = tableProtectSession.verify(le2);
            if (le2.getId() == le.getId()) {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);            	
            } else {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);            	            	
            }
        }
        le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), le.getTime(), le.getUsername(), le.getCertificateSNR(), le.getEvent(), le.getComment());
        entrys.set(3, le1);
        le = (LogEntry)entrys.get(4);
        le1 = new LogEntry(le.getId(), le.getAdminType(), le.getAdminData(), le.getCAId(), le.getModule(), new Date(), le.getUsername(), le.getCertificateSNR(), LogConstants.EVENT_INFO_CAEDITED, le.getComment());
        entrys.set(4, le1);
        iter = entrys.iterator();
        while (iter.hasNext()) {
        	LogEntry le2 = (LogEntry)iter.next();
            TableVerifyResult res = tableProtectSession.verify(le2);
            if (le2.getId() == le.getId()) {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);            	
            } else {
                assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);            	            	
            }
        }
        
        log.trace("<test02VerifyLogEntry()");
    }
    
    /**
     * tests verify protection for cert entrys
     *
     * @throws Exception error
     */
    public void test03VerifyCertEntry() throws Exception {
        log.trace(">test03VerifyCertEntry()");
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        String endEntityFp = CertTools.getFingerprintAsString(cert);
        if (certificateStoreSession.findCertificateByFingerprint(admin, endEntityFp) == null) {
            certificateStoreSession.storeCertificate(admin
                    , cert
                    , "o=AnaTom,c=SE"
                    , endEntityFp
                    , SecConst.CERT_ACTIVE
                    , SecConst.CERTTYPE_ENDENTITY, SecConst.CERTPROFILE_FIXED_ENDUSER, null, new Date().getTime());
        }
        CertificateInfo entry = certificateStoreSession.getCertificateInfo(admin, endEntityFp);
        entry.setFingerprint("1");
        tableProtectSession.protect(entry);        	        
        TableVerifyResult res = tableProtectSession.verify(entry);
        assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);
        entry.setStatus(RevokedCertInfo.REVOKATION_REASON_AACOMPROMISE);
        res = tableProtectSession.verify(entry);
        assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);
        tableProtectSession.protect(entry);        	        
        res = tableProtectSession.verify(entry);
        assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);
        entry.setRevocationDate(new Date());
        res = tableProtectSession.verify(entry);
        assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);
        
        log.trace("<test03VerifyCertEntry()");
    }

    /**
     * tests verify protection for cert entrys in external db
     *
     * @throws Exception error
     */
    public void test04VerifyCertEntryExternal() throws Exception {
        log.trace(">test04VerifyCertEntryExternal()");
        String dataSource = "java:/EjbcaDS";
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        String endEntityFp = CertTools.getFingerprintAsString(cert);
        if (certificateStoreSession.findCertificateByFingerprint(admin, endEntityFp) == null) {
            certificateStoreSession.storeCertificate(admin
                    , cert
                    , "o=AnaTom,c=SE"
                    , endEntityFp
                    , SecConst.CERT_ACTIVE
                    , SecConst.CERTTYPE_ENDENTITY, SecConst.CERTPROFILE_FIXED_ENDUSER, null, new Date().getTime());
        }
        CertificateInfo entry = certificateStoreSession.getCertificateInfo(admin, endEntityFp);
        entry.setFingerprint("2");
        tableProtectSession.protectExternal(entry, dataSource);        	        
        TableVerifyResult res = tableProtectSession.verify(entry);
        assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);
        entry.setStatus(RevokedCertInfo.REVOKATION_REASON_AACOMPROMISE);
        res = tableProtectSession.verify(entry);
        assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);
        tableProtectSession.protectExternal(entry, dataSource);        	        
        res = tableProtectSession.verify(entry);
        assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_SUCCESS);
        entry.setRevocationDate(new Date());
        res = tableProtectSession.verify(entry);
        assertEquals(res.getResultCode(), TableVerifyResult.VERIFY_FAILED);
        
        log.trace("<test04VerifyCertEntryExternal()");
    }

    static byte[] testcert = Base64.decode(("MIICBDCCAW0CAQMwDQYJKoZIhvcNAQEEBQAwTDELMAkGA1UEBhMCU0UxEzARBgNV"
            + "BAgTClNvbWUtU3RhdGUxDzANBgNVBAoTBkFuYXRvbTEXMBUGA1UEAxMOU3Vib3Jk"
            + "aW5hdGUgQ0EwHhcNMDMwOTIyMDkxNTEzWhcNMTMwNDIyMDkxNTEzWjBJMQswCQYD"
            + "VQQGEwJTRTETMBEGA1UECBMKU29tZS1TdGF0ZTEPMA0GA1UEChMGQW5hdG9tMRQw"
            + "EgYDVQQDEwtGb29CYXIgVXNlcjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA"
            + "xPpmVYVBzlGJxUfZa6IsHsk+HrMTbHWr/EUkiZIam95t+0SIFZHUers2PIv+GWVp"
            + "TmH/FTXNWVWw+W6bFlb17rfbatAkVfAYuBGRh+nUS/CPTPNw1jDeCuZRweD+DCNr"
            + "icx/svv0Hi/9scUqrADwtO2O7oBy7Lb/Vfa6BOnBdiECAwEAATANBgkqhkiG9w0B"
            + "AQQFAAOBgQAo5RzuUkLdHdAyJIG2IRptIJDOa0xq8eH2Duw9Xa3ieI9+ogCNaqWy"
            + "V5Oqx2lLsdn9CXxAwT/AsqwZ0ZFOJY1V2BgLTPH+vxnPOm0Xu61fl2XLtRBAycva"
            + "9iknwKZ3PCILvA5qjL9VedxiFhcG/p83SnPOrIOdsHykMTvO8/j8mA==").getBytes());
}
