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
import java.util.Calendar;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.DnComponents;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests signing session.
 * 
 * Since all the CAs from "TestCAs" is required, you should run it manually
 * before running this test and "RemoveCAs" after.
 * 
 * @version $Id$
 */
public class PrivateKeyUsageSignSessionTest extends SignSessionCommon {
    private static final Logger log = Logger.getLogger(PrivateKeyUsageSignSessionTest.class);

    private static KeyPair rsakeyPrivKeyUsagePeriod;

    
    private final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SignSessionTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();

        if (rsakeyPrivKeyUsagePeriod == null) {
            rsakeyPrivKeyUsagePeriod = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        }
     
        CaTestCase.createTestCA();
        AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SignSessionTest"));
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        createEndEntity(USER_PRIVKEYUSAGEPERIOD,  SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, caSession.getCAInfo(internalAdmin, getTestCAName()).getCAId());
        
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SignSessionTest"));
        try {
            endEntityManagementSession.deleteUser(internalAdmin, USER_PRIVKEYUSAGEPERIOD);
            log.debug("deleted user: " + USER_PRIVKEYUSAGEPERIOD + ", foo123, " + DN_PRIVKEYUSAGEPERIOD);
        } catch (Exception e) { /* ignore */
            log.debug("a");
        }
        
        CaTestCase.removeTestCA();
    }
    
    @Before
    public void setUp() throws Exception {
  
    }

    @After
    public void tearDown() throws Exception {
       
    }
    
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }


    /**
     * Tests that if the PrivateKeyUsagePeriod extension is not set in the profile
     * it will not be in the certificate.
     * @throws Exception In case of error.
     */
    @Test
    public void testPrivateKeyUsagePeriod_unused() throws Exception {        
    	X509Certificate cert = privateKeyUsageGetCertificate(false, 0L, false, 0L, false);        
        assertNull("Has not the extension", cert.getExtensionValue("2.5.29.16"));
    }
    
    /**
     * Tests setting different notBefore dates. 
     * @throws Exception In case of error.
     */
    @Test
    public void testPrivateKeyUsagePeriod_notBefore() throws Exception {
    	// A: Only PrivateKeyUsagePeriod.notBefore with same as cert
    	privateKeyUsageTestStartOffset(0L);	
        // B: Only PrivateKeyUsagePeriod.notBefore starting 33 days after cert
    	privateKeyUsageTestStartOffset(33 * 24 * 3600L);	
    	// C: Only PrivateKeyUsagePeriod.notBefore starting 5 years after cert
    	privateKeyUsageTestStartOffset(5 * 365 * 24 * 3600L);   	
    	// D: Only PrivateKeyUsagePeriod.notBefore starting 1 second after cert
    	privateKeyUsageTestStartOffset(1L);      
    	// E: Only PrivateKeyUsagePeriod.notBefore starting 5 years before cert
    	privateKeyUsageTestStartOffset(-5 * 365 * 24 * 3600L);
    	// F: Only PrivateKeyUsagePeriod.notBefore starting 33 days before cert
    	privateKeyUsageTestStartOffset(-33 * 24 * 3600L); 	
    	// G: Only PrivateKeyUsagePeriod.notBefore starting 1 second before cert
    	privateKeyUsageTestStartOffset(-1L);
    }
    
    /**
     * Tests setting different notAfter dates.
     * @throws Exception In case of error.
     */
    @Test
    public void testPrivateKeyUsagePeriod_notAfter() throws Exception {
        

        // 1: Only PrivateKeyUsagePeriod.notAfter 33 days after issuance
    	privateKeyUsageTestValidityLength(33 * 24 * 3600L);
    	
    	// 2: Only PrivateKeyUsagePeriod.notAfter 5 years after issuance
    	privateKeyUsageTestValidityLength(5 * 365 * 24 * 3600L);
    	
    	// 3: :Only PrivateKeyUsagePeriod.notAfter 1 second after issuance
    	privateKeyUsageTestValidityLength(1L);
        
    	// 4: Only PrivateKeyUsagePeriod.notAfter with zero validity length (might not be a correct case)
    	privateKeyUsageTestValidityLength(0L);
    }
    
    /**
     * Tests the combinations of different notBefore and notAfter dates.
     * @throws Exception In case of error.
     */
    @Test
    public void testPrivateKeyUsagePeriod_both() throws Exception {
        privateKeyUsagePeriod_both(false);
    }

    /** See that privateKeyUsage period is set correctly when certificate validity override is allowed and used.
     * If we use a custom startDate (allowed through "allowValidityOverride" there will be no CertificateValidity.getValidityOffset()
     * in the cert.getNotBefore, and hence PrivateKeyUsagePeriod must be exactly same as in the certificate and can not use the default certificate
     * validity.
     */
    @Test
    public void testPrivateKeyUsagePeriod_allowvalidityOverride() throws Exception {
        privateKeyUsagePeriod_both(true);
    }

    private void privateKeyUsagePeriod_both(boolean allowValidityOverride) throws Exception {        
    	// A: 1, 2, 3, 4
    	privateKeyUsageTestBoth(0L, 33 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(0L, 5 * 365 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(0L, 1L, allowValidityOverride);
    	privateKeyUsageTestBoth(0L, 0L, allowValidityOverride);
    	
    	// B: 1, 2, 3, 4
    	privateKeyUsageTestBoth(33 * 24 * 3600L, 33 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(33 * 24 * 3600L, 5 * 365 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(33 * 24 * 3600L, 1L, allowValidityOverride);
    	privateKeyUsageTestBoth(33 * 24 * 3600L, 0L, allowValidityOverride);
    	
    	// C: 1, 2, 3, 4
    	privateKeyUsageTestBoth(5 * 365 * 24 * 3600L, 33 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(5 * 365 * 24 * 3600L, 5 * 365 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(5 * 365 * 24 * 3600L, 1L, allowValidityOverride);
    	privateKeyUsageTestBoth(5 * 365 * 24 * 3600L, 0L, allowValidityOverride);
    	
    	// D: 1, 2, 3, 4
    	privateKeyUsageTestBoth(1L, 33 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(1L, 5 * 365 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(1L, 1L, allowValidityOverride);
    	privateKeyUsageTestBoth(1L, 0L, allowValidityOverride);
        
    	// E: 1, 2, 3, 4
    	privateKeyUsageTestBoth(-5 * 365 * 24 * 3600L, 33 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(-5 * 365 * 24 * 3600L, 5 * 365 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(-5 * 365 * 24 * 3600L, 1L, allowValidityOverride);
    	privateKeyUsageTestBoth(-5 * 365 * 24 * 3600L, 0L, allowValidityOverride);
    	
    	// F: 1, 2, 3, 4
    	privateKeyUsageTestBoth(-33 * 24 * 3600L, 33 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(-33 * 24 * 3600L, 5 * 365 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(-33 * 24 * 3600L, 1L, allowValidityOverride);
    	privateKeyUsageTestBoth(-33 * 24 * 3600L, 0L, allowValidityOverride);
    	
    	// G: 1, 2, 3, 4
    	privateKeyUsageTestBoth(-1L, 33 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(-1L, 5 * 365 * 24 * 3600L, allowValidityOverride);
    	privateKeyUsageTestBoth(-1L, 1L, allowValidityOverride);
    	privateKeyUsageTestBoth(-1L, 0L, allowValidityOverride);
    }
        
    private void privateKeyUsageTestStartOffset(final long startOffset) throws Exception {
    	X509Certificate cert = privateKeyUsageGetCertificate(true, startOffset, false, 0L, false);        
        assertNotNull("Has not the extension", cert.getExtensionValue("2.5.29.16"));
        assertTrue("Extension is non-critical", cert.getNonCriticalExtensionOIDs().contains("2.5.29.16"));
        PrivateKeyUsagePeriod ext = PrivateKeyUsagePeriod.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue("2.5.29.16")));
        assertNotNull("Has notBefore", ext.getNotBefore());
        assertNull("Has no notAfter", ext.getNotAfter());
        assertEquals("notBefore " + startOffset + " seconds after ca cert", cert.getNotBefore().getTime() + startOffset * 1000, ext.getNotBefore().getDate().getTime());
    }
    
    private void privateKeyUsageTestValidityLength(final long length) throws Exception {
    	X509Certificate cert = privateKeyUsageGetCertificate(false, 0L, true, length, false);        
        assertNotNull("Has the extension", cert.getExtensionValue("2.5.29.16"));
        assertTrue("Extension is non-critical", cert.getNonCriticalExtensionOIDs().contains("2.5.29.16"));
        PrivateKeyUsagePeriod ext = PrivateKeyUsagePeriod.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue("2.5.29.16")));
        assertNotNull("Has notAfter", ext.getNotAfter());
        assertNull("Has no notBefore", ext.getNotBefore());
        assertEquals("notAfter " + length + " seconds after issue time", cert.getNotBefore().getTime() + length * 1000, ext.getNotAfter().getDate().getTime());
    }
    
    private void privateKeyUsageTestBoth(final long startOffset, final long length, boolean allowValidityOverride) throws Exception {
    	X509Certificate cert = privateKeyUsageGetCertificate(true, startOffset, true, length, allowValidityOverride);        
        assertNotNull("Has the extension", cert.getExtensionValue("2.5.29.16"));
        assertTrue("Extension is non-critical", cert.getNonCriticalExtensionOIDs().contains("2.5.29.16"));
        PrivateKeyUsagePeriod ext = PrivateKeyUsagePeriod.getInstance(X509ExtensionUtil.fromExtensionValue(cert.getExtensionValue("2.5.29.16")));
        assertNotNull("Has notBefore", ext.getNotBefore());
        assertNotNull("Has notAfter", ext.getNotAfter());
        assertEquals("notBefore " + startOffset + " seconds after ca cert", cert.getNotBefore().getTime() + startOffset * 1000, ext.getNotBefore().getDate().getTime());
        assertEquals("notAfter " + length + " seconds after notBefore", ext.getNotBefore().getDate().getTime() + length * 1000, ext.getNotAfter().getDate().getTime());
    }
    
    private X509Certificate privateKeyUsageGetCertificate(final boolean useStartOffset, final long startOffset, final boolean usePeriod, final long period, boolean allowValidityOverride) throws Exception {
    	
    	certificateProfileSession.removeCertificateProfile(internalAdmin, CERTPROFILE_PRIVKEYUSAGEPERIOD);
    	final CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	certProfile.setAllowValidityOverride(allowValidityOverride);
    	certProfile.setUsePrivateKeyUsagePeriodNotBefore(useStartOffset);
    	certProfile.setPrivateKeyUsagePeriodStartOffset(startOffset);
    	certProfile.setUsePrivateKeyUsagePeriodNotAfter(usePeriod);
    	certProfile.setPrivateKeyUsagePeriodLength(period);
    	certificateProfileSession.addCertificateProfile(internalAdmin, CERTPROFILE_PRIVKEYUSAGEPERIOD, certProfile);
    	final int certProfileId = certificateProfileSession.getCertificateProfileId(CERTPROFILE_PRIVKEYUSAGEPERIOD);
    	endEntityProfileSession.removeEndEntityProfile(internalAdmin, EEPROFILE_PRIVKEYUSAGEPERIOD);
        final EndEntityProfile eeProfile = new EndEntityProfile();
        eeProfile.addField(DnComponents.COUNTRY);
        eeProfile.addField(DnComponents.COMMONNAME);
        eeProfile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS));
        eeProfile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(certProfileId));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, EEPROFILE_PRIVKEYUSAGEPERIOD, eeProfile);
        final int eeProfileId = endEntityProfileSession.getEndEntityProfileId(EEPROFILE_PRIVKEYUSAGEPERIOD);
        int rsacaid = caSession.getCAInfo(internalAdmin, getTestCAName()).getCAId();
        final EndEntityInformation user = new EndEntityInformation(USER_PRIVKEYUSAGEPERIOD, DN_PRIVKEYUSAGEPERIOD, rsacaid, null, "fooprivatekeyusae@example.com", new EndEntityType(EndEntityTypes.ENDUSER), eeProfileId, certProfileId,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword("foo123");
        user.setStatus(EndEntityConstants.STATUS_NEW);
        endEntityManagementSession.changeUser(internalAdmin, user, false);
        
        Calendar cal = Calendar.getInstance();
        Calendar notBefore = Calendar.getInstance();
        notBefore.add(Calendar.DAY_OF_MONTH, 2);
        cal.add(Calendar.DAY_OF_MONTH, 10);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, USER_PRIVKEYUSAGEPERIOD, "foo123",
                new PublicKeyWrapper(rsakeyPrivKeyUsagePeriod.getPublic()), -1, notBefore.getTime(), cal.getTime());
        assertNotNull("Failed to create certificate", cert);
        String dn = cert.getSubjectDN().getName();
        assertEquals(CertTools.stringToBCDNString(DN_PRIVKEYUSAGEPERIOD), CertTools.stringToBCDNString(dn));
        return cert;
    }

}
