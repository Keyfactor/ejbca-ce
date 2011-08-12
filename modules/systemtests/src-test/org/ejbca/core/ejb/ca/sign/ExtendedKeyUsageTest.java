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

package org.ejbca.core.ejb.ca.sign;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests creating certificate with extended key usage.
 * 
 * Works similar to TestSignSession.
 * 
 * @version $Id$
 */
public class ExtendedKeyUsageTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(ExtendedKeyUsageTest.class);

    private static KeyPair rsakeys = null;
    private static int rsacaid = 0;
    private final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

    private CaSessionRemote caSession = InterfaceCache.getCaSession();
    private EndEntityProfileSessionRemote endEntityProfileSession = InterfaceCache.getEndEntityProfileSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    private CertificateProfileSessionRemote certificateProfileSession = InterfaceCache.getCertificateProfileSession();

    @BeforeClass
    public void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
        // Install BouncyCastle provider
       
        if (rsakeys == null) {
            rsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        }
        // Add this again since it will be removed by the other tests in the batch..
        CAInfo inforsa = caSession.getCAInfo(admin, "TEST");
        assertTrue("No active RSA CA! Must have at least one active CA to run tests!", inforsa != null);
        rsacaid = inforsa.getCAId();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        // Delete test end entity profile
        endEntityProfileSession.removeEndEntityProfile(admin, "EXTKEYUSAGECERTPROFILE");
        certificateProfileSession.removeCertificateProfile(admin, "EXTKEYUSAGEEEPROFILE");
        // delete users that we know...
        try {
            userAdminSession.deleteUser(admin, "extkeyusagefoo");
            log.debug("deleted user: foo, foo123, C=SE, O=AnaTom, CN=extkeyusagefoo");
        } catch (Exception e) { /* ignore */
        }

    }

    /**
     * @throws Exception if an error occurs...
     */
    @Test
    public void test01CodeSigning() throws Exception {
        certificateProfileSession.removeCertificateProfile(admin, "EXTKEYUSAGECERTPROFILE");
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ArrayList<String> list = new ArrayList<String>();
        list.add("1.3.6.1.4.1.311.2.1.21"); // MS individual code signing
        list.add("1.3.6.1.4.1.311.2.1.22"); // MS commercial code signing
        certprof.setExtendedKeyUsage(list);
        certificateProfileSession.addCertificateProfile(admin, "EXTKEYUSAGECERTPROFILE", certprof);
        final int fooCertProfile = certificateProfileSession.getCertificateProfileId("EXTKEYUSAGECERTPROFILE");

        endEntityProfileSession.removeEndEntityProfile(admin, "EXTKEYUSAGEEEPROFILE");
        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(fooCertProfile));
        endEntityProfileSession.addEndEntityProfile(admin, "EXTKEYUSAGEEEPROFILE", profile);
        final int fooEEProfile = endEntityProfileSession.getEndEntityProfileId(admin, "EXTKEYUSAGEEEPROFILE");

        createOrEditUser(fooCertProfile, fooEEProfile);

        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "extkeyusagefoo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        // log.debug("Cert=" + cert.toString());
        List<String> ku = cert.getExtendedKeyUsage();
        assertEquals(2, ku.size());
        assertTrue(ku.contains("1.3.6.1.4.1.311.2.1.21"));
        assertTrue(ku.contains("1.3.6.1.4.1.311.2.1.22"));
    }

    /**
     * @throws Exception if an error occurs...
     */
    @Test
    public void test02SSH() throws Exception {
        certificateProfileSession.removeCertificateProfile(admin, "EXTKEYUSAGECERTPROFILE");
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ArrayList<String> list = new ArrayList<String>();
        certprof.setExtendedKeyUsage(list);
        certificateProfileSession.addCertificateProfile(admin, "EXTKEYUSAGECERTPROFILE", certprof);
        final int fooCertProfile = certificateProfileSession.getCertificateProfileId("EXTKEYUSAGECERTPROFILE");

        endEntityProfileSession.removeEndEntityProfile(admin, "EXTKEYUSAGEEEPROFILE");
        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(fooCertProfile));
        endEntityProfileSession.addEndEntityProfile(admin, "EXTKEYUSAGEEEPROFILE", profile);
        final int fooEEProfile = endEntityProfileSession.getEndEntityProfileId(admin, "EXTKEYUSAGEEEPROFILE");

        createOrEditUser(fooCertProfile, fooEEProfile);

        X509Certificate cert = (X509Certificate) signSession.createCertificate(admin, "extkeyusagefoo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        // log.debug("Cert=" + cert.toString());
        List<String> ku = cert.getExtendedKeyUsage();
        assertNull(ku);

        // Now add the SSH extended key usages
        list.add("1.3.6.1.5.5.7.3.21"); // SSH client
        list.add("1.3.6.1.5.5.7.3.22"); // SSH server
        certprof.setExtendedKeyUsage(list);
        certificateProfileSession.changeCertificateProfile(admin, "EXTKEYUSAGECERTPROFILE", certprof);
        createOrEditUser(fooCertProfile, fooEEProfile);
        cert = (X509Certificate) signSession.createCertificate(admin, "extkeyusagefoo", "foo123", rsakeys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        // log.debug("Cert=" + cert.toString());
        ku = cert.getExtendedKeyUsage();
        assertEquals(2, ku.size());
        assertTrue(ku.contains("1.3.6.1.5.5.7.3.21"));
        assertTrue(ku.contains("1.3.6.1.5.5.7.3.22"));
    }

    private void createOrEditUser(final int fooCertProfile, final int fooEEProfile) throws AuthorizationDeniedException,
            UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException, EjbcaException {
        // Make user that we know...
        boolean userExists = false;
        EndEntityInformation user = new EndEntityInformation("extkeyusagefoo", "C=SE,O=AnaTom,CN=extkeyusagefoo", rsacaid, null, "foo@anatom.se",
                SecConst.USER_ENDUSER, fooEEProfile, fooCertProfile, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setStatus(UserDataConstants.STATUS_NEW);
        user.setPassword("foo123");
        try {
            userAdminSession.addUser(admin, user, false);
            log.debug("created user: extkeyusagefoo, foo123, C=SE, O=AnaTom, CN=extkeyusagefoo");
        } catch (Exception re) {
            userExists = true;
        }
        if (userExists) {
            log.info("User extkeyusagefoo already exists, resetting status.");
            userAdminSession.changeUser(admin, user, false);
            log.debug("Reset status to NEW");
        }
    }
}
