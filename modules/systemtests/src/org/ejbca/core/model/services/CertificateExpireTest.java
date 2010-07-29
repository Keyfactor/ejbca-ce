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

package org.ejbca.core.model.services;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.CertificateExpirationNotifierWorker;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.keystore.KeyTools;

/** Tests the certificate expiration notifications.
 *
 * @version $Id$
 */
public class CertificateExpireTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CertificateExpireTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static final String CA_NAME = "CertExpNotifCA";
    private int caid = getTestCAId(CA_NAME);

    private static String username;
    private static String pwd;

    private static final String CERTIFICATE_EXPIRATION_SERVICE = "CertificateExpirationService";

    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private ServiceSessionRemote serviceSession = InterfaceCache.getServiceSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();

    public CertificateExpireTest() {
        super();
    }

    public CertificateExpireTest(String name) {
        super(name);
        CryptoProviderTools.installBCProvider(); // Install BouncyCastle provider
        assertTrue("Could not create TestCA.", createTestCA(CA_NAME));
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * Add a new user and an expire service. Test that the service expires the
     * users password
     * 
     */
    public void test01ExpireCertificate() throws Exception {
        log.trace(">test01CreateNewUser()");

        // Create a new user
        username = genRandomUserName();
        pwd = genRandomPwd();
        userAdminSession.addUser(admin, username, pwd, "C=SE,O=AnaTom,CN=" + username, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, caid);
        log.debug("created user: " + username);

        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, username, pwd, keys.getPublic());
        assertNotNull("Failed to create certificate", cert);

        String fp = CertTools.getFingerprintAsString(cert);
        X509Certificate ce = (X509Certificate) certificateStoreSession.findCertificateByFingerprint(admin, fp);
        assertNotNull("Cannot find certificate with fp=" + fp, ce);
        CertificateInfo info = certificateStoreSession.getCertificateInfo(admin, fp);
        // log.info("Got certificate info for cert with fp="+fp);
        assertEquals("fingerprint does not match.", fp, info.getFingerprint());
        assertEquals("serialnumber does not match.", cert.getSerialNumber(), info.getSerialNumber());
        assertEquals("issuerdn does not match.", CertTools.getIssuerDN(cert), info.getIssuerDN());
        assertEquals("subjectdn does not match.", CertTools.getSubjectDN(cert), info.getSubjectDN());
        // The cert was just stored above with status INACTIVE
        assertEquals("status does not match.", SecConst.CERT_ACTIVE, info.getStatus());
        long seconds = (cert.getNotAfter().getTime() - new Date().getTime()) / 1000l;
        log.debug("ceritificate OK in store, expires in " + seconds + " seconds");

        // Create a new UserPasswordExpireService
        ServiceConfiguration config = new ServiceConfiguration();
        config.setActive(true);
        config.setDescription("This is a description");
        // No mailsending for this Junit test service
        config.setActionClassPath(NoAction.class.getName());
        config.setActionProperties(null);
        config.setIntervalClassPath(PeriodicalInterval.class.getName());
        Properties intervalprop = new Properties();
        // Run the service every 3:rd second
        intervalprop.setProperty(PeriodicalInterval.PROP_VALUE, "3");
        intervalprop.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
        config.setIntervalProperties(intervalprop);
        config.setWorkerClassPath(CertificateExpirationNotifierWorker.class.getName());
        Properties workerprop = new Properties();
        workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "FALSE");
        workerprop.setProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "FALSE");
        workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(caid));
        workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, String.valueOf(seconds - 10));
        workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        config.setWorkerProperties(workerprop);

        serviceSession.addService(admin, CERTIFICATE_EXPIRATION_SERVICE, config);
        serviceSession.activateServiceTimer(admin, CERTIFICATE_EXPIRATION_SERVICE);

        // The service will run...
        Thread.sleep(5000);
        info = certificateStoreSession.getCertificateInfo(admin, fp);
        assertEquals("status does not match.", SecConst.CERT_ACTIVE, info.getStatus());

        // The service will run...since there is a random delay of 30 seconds we
        // have to wait a long time
        Thread.sleep(35000);
        info = certificateStoreSession.getCertificateInfo(admin, fp);
        assertEquals("status does not match.", SecConst.CERT_NOTIFIEDABOUTEXPIRATION, info.getStatus());

        log.trace("<test01CreateNewUser()");
    }

    /**
     * Remove all data stored by JUnit tests
     * 
     */
    public void test99CleanUp() throws Exception {
        log.trace(">test99CleanUp()");
        userAdminSession.deleteUser(admin, username);
        log.debug("Removed user: " + username);
        serviceSession.removeService(admin, CERTIFICATE_EXPIRATION_SERVICE);
        log.debug("Removed service:" + CERTIFICATE_EXPIRATION_SERVICE);
        removeTestCA(CA_NAME);
        log.debug("Removed test CA");
        log.trace("<test99CleanUp()");
    }
}
