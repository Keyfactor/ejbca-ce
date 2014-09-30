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

package org.ejbca.core.model.services;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.services.ServiceDataSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.CertificateExpirationNotifierWorker;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the certificate expiration notifications.
 * 
 * @version $Id$
 */
public class CertificateExpireTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CertificateExpireTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CertificateExpireTest"));
    private static final String USERNAME = "CertificateExpireTest";
    private static final String PASSWORD = "foo123";
    private static final String CA_NAME = "CertExpNotifCA";
    private int caid = getTestCAId(CA_NAME);

    private static final String CERTIFICATE_EXPIRATION_SERVICE = "CertificateExpirationService";

    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private ServiceDataSessionRemote serviceDataSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceDataSessionRemote.class);

    private X509Certificate cert;
    private CertificateInfo info;
    private String fingerprint;
 
    private List<Certificate> certificatesToRemove;
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        createTestCA(CA_NAME);
    }
   
    
    @AfterClass
    public static void afterClass() throws Exception {
        removeTestCA(CA_NAME);
        log.debug("Removed test CA");
    }
    
    @Before
    public void setUp() throws Exception {
        certificatesToRemove = new ArrayList<Certificate>();
        endEntityManagementSession.addUser(admin, USERNAME, PASSWORD, "C=SE,O=AnaTom,CN=" + USERNAME, null, null, false, SecConst.EMPTY_ENDENTITYPROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.TOKEN_SOFT_PEM, 0, caid);
        
    }

    @After
    public void tearDown() throws Exception {      
        for(Certificate certificate : certificatesToRemove) {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
        for(Certificate certificate : internalCertificateStoreSession.findCertificatesByIssuer("CN="+CA_NAME)) {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
        
        endEntityManagementSession.deleteUser(admin, USERNAME);
        log.debug("Removed user: " + USERNAME);
        serviceSession.removeService(admin, CERTIFICATE_EXPIRATION_SERVICE);
        log.debug("Removed service:" + CERTIFICATE_EXPIRATION_SERVICE);
        assertNull("ServiceData object with id 4711 was not removed properly.", serviceDataSession.findById(4711));

    }
    
    private void createCertificate() throws Exception {
        createCertificate(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
    }
    
    private void createCertificate(int certificateProfileId) throws Exception {
        KeyPair keys = KeyTools.genKeys("1024", "RSA");
        cert = (X509Certificate) signSession.createCertificate(admin, USERNAME, PASSWORD, keys.getPublic(), -1, null, null, certificateProfileId,
                SecConst.CAID_USEUSERDEFINED);
        certificatesToRemove.add(cert);
        fingerprint = CertTools.getFingerprintAsString(cert);
        X509Certificate ce = (X509Certificate) certificateStoreSession.findCertificateByFingerprint(fingerprint);
        if(ce == null) {
            throw new Exception("Cannot find certificate with fp=" + fingerprint);
        }
        info = certificateStoreSession.getCertificateInfo(fingerprint);
        if (!fingerprint.equals(info.getFingerprint())) {
            throw new Exception("fingerprint does not match.");
        }
        if (!cert.getSerialNumber().equals(info.getSerialNumber())) {
            throw new Exception("serialnumber does not match.");
        }
        if (!CertTools.getIssuerDN(cert).equals(info.getIssuerDN())) {
            throw new Exception("issuerdn does not match.");
        }
        if (!CertTools.getSubjectDN(cert).equals(info.getSubjectDN())) {
            throw new Exception("subjectdn does not match.");
        }
        // The cert was just stored above with status INACTIVE
        if (!(CertificateConstants.CERT_ACTIVE == info.getStatus())) {
            throw new Exception("status does not match.");
        }
    }
    
    /**
     * Add a new user and an expire service. Test that the service expires the
     * users password
     * 
     */
    @Test
    public void testExpireCertificate() throws Exception {
        createCertificate();
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
        workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, String.valueOf(seconds - 5));
        workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        config.setWorkerProperties(workerprop);

        if (serviceSession.getService(CERTIFICATE_EXPIRATION_SERVICE) == null) {
            serviceSession.addService(admin, 4711, CERTIFICATE_EXPIRATION_SERVICE, config);
        }
        serviceSession.activateServiceTimer(admin, CERTIFICATE_EXPIRATION_SERVICE);

        // The service will run... the cert should still be active after 5 seconds..
        Thread.sleep(2000);
        info = certificateStoreSession.getCertificateInfo(fingerprint);
        assertEquals("status does not match.", CertificateConstants.CERT_ACTIVE, info.getStatus());
        // The service will run...We need some tolerance since timers cannot
        // be guaranteed to executed at the exact interval. 
        Thread.sleep(3000);
        int tries = 0;
        while (info.getStatus() != CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION && tries<5) {
        	Thread.sleep(1000);
        	info = certificateStoreSession.getCertificateInfo(fingerprint);
        	tries++;
        }
        info = certificateStoreSession.getCertificateInfo(fingerprint);
        assertEquals("Status does not match.", CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION, info.getStatus());
    	log.debug("It took >" + (9+tries) + " seconds before the certificate was expired!");

    }

    /**
     * Add a new user and an expire service. Test running on all CAs.
     * 
     */
    @Test
    public void testExpireCertificateWithAllCAs() throws Exception {
        try {
        createCertificate();
        long seconds = (cert.getNotAfter().getTime() - new Date().getTime()) / 1000l;
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
        //Here is the line that matters for this test
        workerprop.setProperty(BaseWorker.PROP_CAIDSTOCHECK, String.valueOf(SecConst.ALLCAS));
        
        workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, String.valueOf(seconds - 5));
        workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
        config.setWorkerProperties(workerprop);
        if (serviceSession.getService(CERTIFICATE_EXPIRATION_SERVICE) == null) {
            serviceSession.addService(admin, 4711, CERTIFICATE_EXPIRATION_SERVICE, config);
        }
        serviceSession.activateServiceTimer(admin, CERTIFICATE_EXPIRATION_SERVICE);
        // The service will run... the cert should still be active after 2
        // seconds..
        Thread.sleep(2000);
        info = certificateStoreSession.getCertificateInfo(fingerprint);
        assertEquals("status does not match.", CertificateConstants.CERT_ACTIVE, info.getStatus());
        // The service will run...We need some tolerance since timers cannot
        // be guaranteed to executed at the exact interval.
        Thread.sleep(10000);
        int tries = 0;
        while (info.getStatus() != CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION && tries < 8) {
            Thread.sleep(1000);
            info = certificateStoreSession.getCertificateInfo(fingerprint);
            tries++;
        }
        info = certificateStoreSession.getCertificateInfo(fingerprint);
        assertEquals("Status does not match.", CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION, info.getStatus());
        } finally {
            //Restore superadmin CA if it got screwed up.
            List<Certificate> certs = certificateStoreSession.findCertificatesByUsername("superadmin");
            for (Certificate certificate : certs) {
                String superAdminFingerprint = CertTools.getFingerprintAsString(certificate);
                internalCertificateStoreSession.setStatus(admin, superAdminFingerprint, CertificateConstants.CERT_ACTIVE);
            }
        }
    }
    
    /**
     * Add a new user and an expire service. Test that the service expires the
     * users password
     * 
     */
    @Test
    public void testExpireCertificateWithCertificateProfiles() throws Exception {
        final String certificateprofilename = "testExpireCertificateWithCertificateProfiles";
        int certificateProfileId = certificateProfileSession.addCertificateProfile(admin, certificateprofilename, new CertificateProfile());
        try {
            createCertificate(certificateProfileId);
            long seconds = (cert.getNotAfter().getTime() - new Date().getTime()) / 1000l;
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
            workerprop.setProperty(BaseWorker.PROP_CERTIFICATE_PROFILE_IDS_TO_CHECK, Integer.toString(certificateProfileId));
            workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, String.valueOf(seconds - 5));
            workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
            config.setWorkerProperties(workerprop);
            if (serviceSession.getService(CERTIFICATE_EXPIRATION_SERVICE) == null) {
                serviceSession.addService(admin, 4711, CERTIFICATE_EXPIRATION_SERVICE, config);
            }
            serviceSession.activateServiceTimer(admin, CERTIFICATE_EXPIRATION_SERVICE);
            // The service will run... the cert should still be active after 2
            // seconds..
            Thread.sleep(2000);
            info = certificateStoreSession.getCertificateInfo(fingerprint);
            assertEquals("status does not match.", CertificateConstants.CERT_ACTIVE, info.getStatus());
            // The service will run...We need some tolerance since timers cannot
            // be guaranteed to executed at the exact interval.
            Thread.sleep(10000);
            int tries = 0;
            while (info.getStatus() != CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION && tries < 5) {
                Thread.sleep(1000);
                info = certificateStoreSession.getCertificateInfo(fingerprint);
                tries++;
            }
            info = certificateStoreSession.getCertificateInfo(fingerprint);
            assertEquals("Status does not match.", CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION, info.getStatus());
        } finally {
            //Clean the certificate profile
            certificateProfileSession.removeCertificateProfile(admin, certificateprofilename);
        }
    }
    
    /**
     * Tries performing the certificate expire worker based on a certificate profile which isn't used. 
     */
    @Test
    public void testExpireCertificateUnusedCertificateProfile() throws Exception {
        final String usedCertificateprofilename = "foo";
        final String unusedCertificateProfileName = "bar";
        int usedCertificateProfileId = certificateProfileSession.addCertificateProfile(admin, usedCertificateprofilename, new CertificateProfile());
        int unusedCertificateProfileId = certificateProfileSession.addCertificateProfile(admin, unusedCertificateProfileName, new CertificateProfile());
        try {
            createCertificate(usedCertificateProfileId);
            long seconds = (cert.getNotAfter().getTime() - new Date().getTime()) / 1000l;
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
            //Use the unused certificate profile on the worker.
            workerprop.setProperty(BaseWorker.PROP_CERTIFICATE_PROFILE_IDS_TO_CHECK, Integer.toString(unusedCertificateProfileId));
            workerprop.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, String.valueOf(seconds - 5));
            workerprop.setProperty(BaseWorker.PROP_TIMEUNIT, BaseWorker.UNIT_SECONDS);
            config.setWorkerProperties(workerprop);
            if (serviceSession.getService(CERTIFICATE_EXPIRATION_SERVICE) == null) {
                serviceSession.addService(admin, 4711, CERTIFICATE_EXPIRATION_SERVICE, config);
            }
            serviceSession.activateServiceTimer(admin, CERTIFICATE_EXPIRATION_SERVICE);
            // The service will run... the cert should still be active after 2
            // seconds..
            Thread.sleep(2000);
            info = certificateStoreSession.getCertificateInfo(fingerprint);
            assertEquals("status does not match.", CertificateConstants.CERT_ACTIVE, info.getStatus());
            // The service will run...We need some tolerance since timers cannot
            // be guaranteed to executed at the exact interval.
            Thread.sleep(10000);
            int tries = 0;
            while (info.getStatus() != CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION && tries < 5) {
                Thread.sleep(1000);
                info = certificateStoreSession.getCertificateInfo(fingerprint);
                tries++;
            }
            info = certificateStoreSession.getCertificateInfo(fingerprint);
            assertEquals("Status has unduly been changed", CertificateConstants.CERT_ACTIVE, info.getStatus());
        } finally {
            //Clean the certificate profile
            certificateProfileSession.removeCertificateProfile(admin, usedCertificateprofilename);
            certificateProfileSession.removeCertificateProfile(admin, unusedCertificateProfileName);
        }
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

}
