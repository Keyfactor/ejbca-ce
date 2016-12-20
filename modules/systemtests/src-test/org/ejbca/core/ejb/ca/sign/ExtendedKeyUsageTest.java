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

package org.ejbca.core.ejb.ca.sign;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
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
    
    private static final String CERT_PROFILE_NAME = "EXTKEYUSAGECERTPROFILE";
    private static final String EE_PROFILE_NAME = "EXTKEYUSAGEEEPROFILE";
    
    private static KeyPair rsakeys = null;
    private static int rsacaid = 0;
    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ExtendedKeyUsageTest"));
    
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);;
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() {
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
        CAInfo inforsa = caSession.getCAInfo(internalAdmin, "TEST");
        assertTrue("No active RSA CA! Must have at least one active CA to run tests!", inforsa != null);
        rsacaid = inforsa.getCAId();
        

    }

    @After
    public void tearDown() throws Exception {
        try {
            super.tearDown();
        } catch (Exception e) {
            //NOPMD: Ignore
        }
        // Delete test end entity profile
        endEntityProfileSession.removeEndEntityProfile(internalAdmin, EE_PROFILE_NAME);
        certificateProfileSession.removeCertificateProfile(internalAdmin, CERT_PROFILE_NAME);
        // delete users that we know...
        try {
            endEntityManagementSession.deleteUser(internalAdmin, "extkeyusagefoo");
            log.debug("deleted user: foo, foo123, C=SE, O=AnaTom, CN=extkeyusagefoo");
        } catch (Exception e) { //NOPMD: Ignore
        }
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    /**
     * @throws Exception if an error occurs...
     */
    @Test
    public void test01CodeSigning() throws Exception {
        certificateProfileSession.removeCertificateProfile(internalAdmin, CERT_PROFILE_NAME);
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ArrayList<String> list = new ArrayList<String>();
        list.add("1.3.6.1.4.1.311.2.1.21"); // MS individual code signing
        list.add("1.3.6.1.4.1.311.2.1.22"); // MS commercial code signing
        certprof.setExtendedKeyUsage(list);
        certificateProfileSession.addCertificateProfile(internalAdmin, CERT_PROFILE_NAME, certprof);
        final int fooCertProfile = certificateProfileSession.getCertificateProfileId(CERT_PROFILE_NAME);

        endEntityProfileSession.removeEndEntityProfile(internalAdmin, EE_PROFILE_NAME);
        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(fooCertProfile));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, EE_PROFILE_NAME, profile);
        final int fooEEProfile = endEntityProfileSession.getEndEntityProfileId(EE_PROFILE_NAME);

        createOrEditUser(fooCertProfile, fooEEProfile);

        X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, "extkeyusagefoo", "foo123", new PublicKeyWrapper(rsakeys.getPublic()));
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
     
        certificateProfileSession.removeCertificateProfile(internalAdmin, CERT_PROFILE_NAME);
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ArrayList<String> list = new ArrayList<String>();
        certprof.setExtendedKeyUsage(list);
        certificateProfileSession.addCertificateProfile(internalAdmin, CERT_PROFILE_NAME, certprof);
        final int fooCertProfile = certificateProfileSession.getCertificateProfileId(CERT_PROFILE_NAME);

        endEntityProfileSession.removeEndEntityProfile(internalAdmin, EE_PROFILE_NAME);
        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(fooCertProfile));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, EE_PROFILE_NAME, profile);
        final int fooEEProfile = endEntityProfileSession.getEndEntityProfileId(EE_PROFILE_NAME);

        createOrEditUser(fooCertProfile, fooEEProfile);

        X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, "extkeyusagefoo", "foo123", new PublicKeyWrapper(rsakeys.getPublic()));
        assertNotNull("Failed to create certificate", cert);
        // log.debug("Cert=" + cert.toString());
        List<String> ku = cert.getExtendedKeyUsage();
        assertNull(ku);

        // Now add the SSH extended key usages
        list.add("1.3.6.1.5.5.7.3.21"); // SSH client
        list.add("1.3.6.1.5.5.7.3.22"); // SSH server
        certprof.setExtendedKeyUsage(list);
        certificateProfileSession.changeCertificateProfile(internalAdmin, CERT_PROFILE_NAME, certprof);
        createOrEditUser(fooCertProfile, fooEEProfile);
        cert = (X509Certificate) signSession.createCertificate(internalAdmin, "extkeyusagefoo", "foo123", new PublicKeyWrapper(rsakeys.getPublic()));
        assertNotNull("Failed to create certificate", cert);
        // log.debug("Cert=" + cert.toString());
        ku = cert.getExtendedKeyUsage();
        assertEquals(2, ku.size());
        assertTrue(ku.contains("1.3.6.1.5.5.7.3.21"));
        assertTrue(ku.contains("1.3.6.1.5.5.7.3.22"));
    }

    private void createOrEditUser(final int fooCertProfile, final int fooEEProfile)
            throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException,
            EjbcaException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException {
        // Make user that we know...
        boolean userExists = false;
        EndEntityInformation user = new EndEntityInformation("extkeyusagefoo", "C=SE,O=AnaTom,CN=extkeyusagefoo", rsacaid, null, "foo@anatom.se",
                new EndEntityType(EndEntityTypes.ENDUSER), fooEEProfile, fooCertProfile, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword("foo123");
        try {
            endEntityManagementSession.addUser(internalAdmin, user, false);
            log.debug("created user: extkeyusagefoo, foo123, C=SE, O=AnaTom, CN=extkeyusagefoo");
        } catch (Exception re) {
            userExists = true;
        }
        if (userExists) {
            log.info("User extkeyusagefoo already exists, resetting status.");
            endEntityManagementSession.changeUser(internalAdmin, user, false);
            log.debug("Reset status to NEW");
        }
    }
}
