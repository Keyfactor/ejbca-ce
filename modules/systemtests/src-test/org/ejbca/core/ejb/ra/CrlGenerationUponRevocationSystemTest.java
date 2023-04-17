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
package org.ejbca.core.ejb.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaMsCompatibilityIrreversibleException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runners.MethodSorters;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Tests CRL generation upon revocation (CA setting).
 *
 * Involves certificate profiles single active certificate constraint functionality (SACC). 
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class CrlGenerationUponRevocationSystemTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CrlGenerationUponRevocationSystemTest.class);

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("CrlGenerationUponRevocationSystemTest");
    private static final ArrayList<String> usernames = new ArrayList<>();

    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final EndEntityAuthenticationSessionRemote endEntityAuthenticationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityAuthenticationSessionRemote.class);       
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    
    private final int caId = getTestCAId();
    private String caName = getTestCAName(); // Cannot be changed...
    private X509CAInfo caInfo;
    
    private static String username;
    private String pwd;
    private String endEntityProfileName;
    private String certificateProfileName;
    private static long deltaCrlPeriod = 0L;
    private static boolean useMultipleCas = false;
    
    private final int caId2 = getTestCAId2();
    private String caName2 = getTestCAName() + "-CA2";
    private X509CAInfo caInfo2;
    private String endEntityProfileName2;
    private String certificateProfileName2;
    
    private final int caId3 = getTestCAId3();
    private String caName3 = getTestCAName() + "-CA3";
    private X509CAInfo caInfo3;
    private String endEntityProfileName3;
    private String certificateProfileName3;
    
    public static int getTestCAId2() {
        return getTestCAId(getTestCAName() + "-CA2");
    }
    
    public static void removeTestCA2() throws AuthorizationDeniedException {
        removeTestCA(getTestCAName() + "-CA2");
    }
    
    public static int getTestCAId3() {
        return getTestCAId(getTestCAName() + "-CA3");
    }
    
    public static void removeTestCA3() throws AuthorizationDeniedException {
        removeTestCA(getTestCAName() + "-CA3");
    }
    
    private static final Set<X509CAInfo> casToDelete = new HashSet<>();
    private static final Set<String> certificateProfilesToDelete = new HashSet<>();
    private static final Set<String> endEntityProfilesToDelete = new HashSet<>();
    private static final Set<X509Certificate> certificatesToDelete = new HashSet<>();
    
    @Rule
    public final TestWatcher traceLogMethodsRule = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            log.trace(">" + description.getMethodName());
            super.starting(description);
        };

        @Override
        protected void finished(final Description description) {
            log.trace("<" + description.getMethodName());
            super.finished(description);
        }
    };

    @BeforeClass    
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        log.trace(">CrlGenerationUponRevocationSystemTest.setUp(deltaCrlPeriod=" + deltaCrlPeriod + ")");
        username = genRandomUserName();
        pwd = genRandomPwd();
        endEntityProfileName = genRandomUserName();
        certificateProfileName = genRandomUserName();
        
        super.setUpAuthTokenAndRole(getRoleName() + "Base");
        removeTestCA(); // We can't be sure this CA was not left over from
        
        caInfo = createTestCAWithGenerateCrlUponRevocation(caName, deltaCrlPeriod);
        createCertificateProfile(certificateProfileName, caId);
        createEndEntityProfile(endEntityProfileName, certificateProfileName, caId);
        
        if (useMultipleCas) {
            endEntityProfileName2 = genRandomUserName();
            certificateProfileName2 = genRandomUserName();
            endEntityProfileName3 = genRandomUserName();
            certificateProfileName3 = genRandomUserName();
        
            removeTestCA2();
            removeTestCA3();
            
            caInfo2 = createTestCAWithGenerateCrlUponRevocation(caName2, deltaCrlPeriod);
            createCertificateProfile(certificateProfileName2, caId2);
            createEndEntityProfile(endEntityProfileName2, certificateProfileName2, caId2);
            
            caInfo3 = createTestCAWithGenerateCrlUponRevocation(caName3, deltaCrlPeriod);
            createCertificateProfile(certificateProfileName3, caId3);
            createEndEntityProfile(endEntityProfileName3, certificateProfileName3, caId3);
        }
        
        addDefaultRole();
        addUser(endEntityProfileName, certificateProfileName);
    }

    @After
    public void teardown() throws Exception {
        super.tearDown();
        try {
            if (useMultipleCas) {
                removeTestCA2();
                removeTestCA3();
            }
            deleteUserAndCertificates();
            deleteProfiles();
        } catch(Exception e) {
            log.warn("Failed to delete test data: " + e.getMessage(), e);
        }
    }
    
    @AfterClass    
    public static void afterClass() {
        try {
            removeTestCA();
            removeTestCA2();
            removeTestCA3();
            deleteUserAndCertificates();
            deleteProfiles();
        } catch(Exception e) {
            log.warn("Failed to delete test data: " + e.getMessage(), e);
        }
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @Test
    public void test01RevokeCertificate() throws Exception {
        // Initial CRLs.
        final String subjectDn = caInfo.getSubjectDN();
        assertCrlNumbers(subjectDn, 1, 0);

        // Issue first certificate.
        final X509Certificate certificate = issueTestCertificate();
        final BigInteger serial = CertTools.getSerialNumber(certificate);
        
        // Still same CRLs.
        assertCrlNumbers(subjectDn, 1, 0);

        // Revoke the certificate, put on hold
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, serial, subjectDn);
        assertCrlEntry(subjectDn, certificate, true);
        
        // Reactivate the certificate
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.NOT_REVOKED, serial, subjectDn);
        assertCrlEntry(subjectDn, certificate, false);

        // Revoke the certificate, put on hold
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, serial, subjectDn);
        assertCrlEntry(subjectDn, certificate, true);

        // For the following tests in sequence.
        deltaCrlPeriod = 10 * SimpleTime.MILLISECONDS_PER_HOUR;
    }
    
    // Tests with Delta CRLs.
    
    @Test
    public void test02RevokeCertificateIncludingDeltaCrls() throws Exception {
        // Initial CRLs.
        final String subjectDn = caInfo.getSubjectDN();
        assertCrlNumbers(subjectDn, 1, 2);
        
        // Issue first certificate.
        final X509Certificate certificate = issueTestCertificate();
        final BigInteger serial = CertTools.getSerialNumber(certificate);
        
        // Still same CRLs.
        assertCrlNumbers(subjectDn, 1, 2);
        
        // Revoke the certificate, put on hold
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, serial, subjectDn);
        assertCrlEntry(subjectDn, certificate, true);

        // Reactivate the certificate
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.NOT_REVOKED, serial, subjectDn);
        assertCrlEntry(subjectDn, certificate, false);

        // Revoke the certificate, put on hold
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, serial, subjectDn);
        assertCrlEntry(subjectDn, certificate, true);
    }
    
    /**
     * Creates a certificate with single active certificate constraint (SACC) enabled in 
     * certificate profile for one identity having one valid certificate issued by the 
     * same CA and generates one CRL upon revocation. 
     *  
     * @throws Exception any exception.
     */
    @Test
    public void test03CreateCertificateWithSaccAndGenerateCrl() throws Exception {
        // Initial CRLs.
        final String subjectDn = caInfo.getSubjectDN();
        assertCrlNumbers(subjectDn, 1, 2);
        
        // Issue first certificate.
        final X509Certificate certificate = issueTestCertificate();
        
        // Still same CRLs.
        assertCrlNumbers(subjectDn, 1, 2);

        // Issue second certificate.
        @SuppressWarnings("unused")
        final X509Certificate nextCertificate = issueTestCertificate();
        
        // First certificate must have been revoked because of SACC.
        assertRevocationStatus(certificate, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
        
        // CRL must have been generated upon revocation.
        assertCrlNumbers(subjectDn, 3, 4);
        
        // CRL must include the revoked certificate.
        assertCrlEntry(subjectDn, certificate, true);
        
        useMultipleCas = true;
    }

    /**
     * Creates one certificate with single active certificate constraint (SACC) enabled or 
     * disabled in certificate profiles concerned for one identity having multiple valid certificates
     * issued by several CAs and generates CRLs upon revocation.
     *  
     * @throws Exception any exception.
     */
    @SuppressWarnings("unused")
    @Test
    public void test04CreateCertificatesWithSaccAndGenerateCrls() throws Exception {
        // Initial CRLs.
        final String subjectDn = caInfo.getSubjectDN();
        assertCrlNumbers(subjectDn, 1, 2);
        
        // Issue first certificate.
        final X509Certificate certificate = issueTestCertificate();
        
        // Still same CRLs.
        assertCrlNumbers(subjectDn, 1, 2);
        
        // Disable SACC for first certificate profile.
        updateCertificateProfileSacc(certificateProfileName, false);
        
        final X509Certificate secondCertificate = issueTestCertificate();
        
        // Still same CRLs.
        assertCrlNumbers(subjectDn, 1, 2);
        
        final X509Certificate thirdCertificate = issueTestCertificate();
        
        // Still same CRLs.
        assertCrlNumbers(subjectDn, 1, 2);
        
        // Enable SACC for first certificate profile, disable for second.
        updateCertificateProfileSacc(certificateProfileName, true);
        updateCertificateProfileSacc(certificateProfileName2, false);
        
        // Update user for enrollment with second CA.
        updateUser(caId2, endEntityProfileName2, certificateProfileName2);
        
        final X509Certificate fourthCertificate = issueTestCertificate();
        
        final X509Certificate fifthCertificate = issueTestCertificate();
        
        // Still same CRLs for first and second CA.
        assertCrlNumbers(subjectDn, 1, 2);
        final String subjectDn2 = caInfo2.getSubjectDN();
        assertCrlNumbers(subjectDn2, 1, 2);
        
        // Enable SACC for second certificate profile, disable for the third.
        updateCertificateProfileSacc(certificateProfileName2, true);
        updateCertificateProfileSacc(certificateProfileName3, false);
        
        // Update user for enrollment with third CA.
        updateUser(caId3, endEntityProfileName3, certificateProfileName3);
        
        final X509Certificate sixthCertificate = issueTestCertificate();
        
        // Still same CRLs for all CAs.
        assertCrlNumbers(subjectDn, 1, 2);
        assertCrlNumbers(subjectDn2, 1, 2);
        final String subjectDn3 = caInfo3.getSubjectDN();
        assertCrlNumbers(subjectDn3,1, 2);
        
        // Enable SACC for third certificate profile.
        updateCertificateProfileSacc(certificateProfileName3, true);
        
        // Disable CRL generation upon generation for second CA.
        updateCaCrlGenerationUponRevocation(caInfo2, false);
        
        final X509Certificate seventhCertificate = issueTestCertificate();
        
        // Second CA did not created a CRL upon revocation because disabled.
        assertCrlNumbers(subjectDn, 3, 4);
        assertCrlNumbers(subjectDn2, 1, 2);
        assertCrlNumbers(subjectDn3, 3, 4);
        
        // First CA CRL must include 3 revoked certificates.
        assertCrlEntry(subjectDn, certificate, true);
        assertCrlEntry(subjectDn, secondCertificate, true);
        assertCrlEntry(subjectDn, thirdCertificate, true);
        
        // Third CA CRL must include 1 revoked certificate.
        assertCrlEntry(subjectDn3, sixthCertificate, true);
        
        useMultipleCas = false;
    }

    private final void revokeCertificateAndAssertCrlGeneration(final int revocationReason, final BigInteger serial, final String subjectDn)
            throws Exception {
        final int crlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, false);
        final int deltaCrlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, true);

        endEntityManagementSession.revokeCert(admin, serial, subjectDn, revocationReason);
        final CertificateStatus status = certificateStoreSession.getStatus(subjectDn, serial);
        assertEquals(revocationReason, status.revocationReason);

        if (deltaCrlPeriod > 0L) {
            assertCrlNumbers(subjectDn, crlNumber + 2, deltaCrlNumber + 2);
        } else {
            assertCrlNumbers(subjectDn, crlNumber + 1, 0);
        }
    }

    /**
     * Tests creation of new user and duplicate user
     * 
     * @throws Exception any exception.
     */
    private void addUser(final String endEntityProfileName, final String certificateProfileName) throws Exception {
        log.trace(">addUser()");

        final String email = username + "@primekey.com";
        final int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
        final int certificateProfileId = certificateProfileSession.getCertificateProfileId(certificateProfileName);
        final EndEntityInformation eeInfo = new EndEntityInformation(username, "C=SE, O=PrimeKey, CN=" + username, caId, "rfc822name=" + email, email,
                EndEntityTypes.ENDUSER.toEndEntityType(), endEntityProfileId, certificateProfileId, SecConst.TOKEN_SOFT_P12, null);
        eeInfo.setStatus(EndEntityConstants.STATUS_NEW);
        eeInfo.setPassword(pwd);
        endEntityManagementSession.addUser(admin, eeInfo, false);
        usernames.add(username);
        
        log.debug("Created user '" + username + "', '" + pwd + "', C=SE, O=Primekey, CN=" + username);

        // Add the same user again
        boolean userExists = false;
        try {
            endEntityManagementSession.addUser(admin, eeInfo, false);
        } catch (EndEntityExistsException e) {
            userExists = true; // This is what we want
        }
        assertTrue("Trying to create the same user twice didn't throw EndEntityExistsException", userExists);
        log.trace("<addUser()");
    }
    
    private void updateUser(final int caId, final String endEntityProfileName, final String certificateProfileName) {
        try {
            final EndEntityInformation eeInfo = endEntityAuthenticationSession.authenticateUser(admin, username, pwd);
            final int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
            final int certificateProfileId = certificateProfileSession.getCertificateProfileId(certificateProfileName);
            eeInfo.setCAId(caId);
            eeInfo.setEndEntityProfileId(endEntityProfileId);
            eeInfo.setCertificateProfileId(certificateProfileId);
            endEntityManagementSession.changeUser(admin, eeInfo, true);
        } catch (Exception e) {
            fail("Failed to update end entity '" + username + "'.");
        }
    }
 
    private final X509CAInfo createTestCAWithGenerateCrlUponRevocation(final String caName, final long deltaCrlPeriod) throws Exception {
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(admin, caName, "2048", "2048", CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);

        log.debug("Creating CryptoToken with ID " + cryptoTokenId + " to be used by CA " + caName);
        final CAToken caToken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, CAToken.SOFTPRIVATESIGNKEYALIAS, CAToken.SOFTPRIVATEDECKEYALIAS);
        X509CAInfo caInfo = X509CAInfo.getDefaultX509CAInfo("CN=" + caName, caName, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, caToken);
        caInfo.setDescription("JUnit RSA CA");
        caInfo.setGenerateCrlUponRevocation(true);
        caInfo.setDeltaCRLPeriod(deltaCrlPeriod);
        caInfo.setUseCRLNumber(true);
        caInfo.setFinishUser(false);
        try {
            caAdminSession.createCA(admin, caInfo);
        } catch (Exception e) {
            log.error("Could not create CA: " + e.getMessage(), e);
            fail("Could not create CA: " + e.getMessage());
        }
        caInfo = (X509CAInfo) caSession.getCAInfo(admin, caName);
        assertNotNull("Test CA must not be null.", caInfo);
        
        final X509Certificate cert = (X509Certificate) caInfo.getCertificateChain().iterator().next();

        // Re-factor.
        final String normalizedDN = CertTools.stringToBCDNString("CN=" + caName);
        final String normalizedCertDN = CertTools.stringToBCDNString(cert.getSubjectDN().toString());
        String message = null;
        if (!normalizedCertDN.equals(normalizedDN)) {
            message = "CA certificate DN is not what it should. Is '" + normalizedDN + "'. Should be '" + normalizedCertDN + "'.";
            log.error(message);
            fail(message);
        }
        if (!caInfo.getSubjectDN().equals(normalizedCertDN)) {
            message = "Creating CA failed!";
            log.error(message);
            fail(message);
        }
        if (certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert)) == null) {
            message = "CA certificate not available in database!!";
            log.error(message);
            fail(message);
        }
        assertEquals("Test CA was not active after creation.", CAConstants.CA_ACTIVE, caInfo.getStatus());
        
        if (deltaCrlPeriod > 0) {
            assertCrlNumbers(caInfo.getSubjectDN(), 1, 2);
        } else {
            assertCrlNumbers(caInfo.getSubjectDN(), 1, 0);
        }
        
        log.trace("<createTestCA: " + caInfo.getCAId());
        casToDelete.add(caInfo);
        return caInfo;
    }
    
    private void updateCaCrlGenerationUponRevocation(final X509CAInfo caInfo, final boolean enabled) {
        caInfo2.setGenerateCrlUponRevocation(enabled);
        try {
            caSession.editCA(admin, caInfo);
        } catch (CADoesntExistsException | InternalKeyBindingNonceConflictException | AuthorizationDeniedException | CaMsCompatibilityIrreversibleException e) {
            log.error(e);
            fail("Failed to updae CA '" + caInfo.getName() + "': " + e.getMessage());
        }
    }
    
    private CertificateProfile createCertificateProfile(final String name, final int caId) throws Exception {
        final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        profile.setSingleActiveCertificateConstraint(true);
        profile.setAvailableCAs(Collections.singletonList(caId));
        certificateProfileSession.addCertificateProfile(admin, name, profile);
        assertNotNull("Test certificate profile '" + name + "' must not be null.", profile);
        certificateProfilesToDelete.add(name);
        return profile;
    }
    
    private EndEntityProfile createEndEntityProfile(final String name, final String certificateProfileName, final int caId) throws Exception {
        final EndEntityProfile profile = new EndEntityProfile(true);
        final int certificateProfileId = certificateProfileSession.getCertificateProfileId(certificateProfileName);
        profile.setAvailableCertificateProfileIds(Collections.singletonList(certificateProfileId));
        profile.setDefaultCertificateProfile(certificateProfileId);
        profile.setDefaultCA(caId);
        endEntityProfileSession.addEndEntityProfile(admin, name, profile);
        assertNotNull("Test end entity profile '" + name + "' must not be null.", profile);
        endEntityProfilesToDelete.add(name);
        return profile;
    }
    
    private void assertCrlNumbers(final String subjectDn, final int crlNumber, final int deltaCrlNumber) {
        final int currentCrlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, false);
        final int currentDeltaCrlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, true);
        assertEquals("CRL number must be " + crlNumber + ".", crlNumber, currentCrlNumber);
        assertEquals("Delta CRL number must be " + deltaCrlNumber + ".", deltaCrlNumber, currentDeltaCrlNumber);
    }
    
    private void assertCrlEntry(final String subjectDn, final X509Certificate certificate, final boolean isInCrl) {
        if (isInCrl) {
            assertNotNull("Revoked certificates must be included in latest CRL.", crlStoreSession.getLastCRLInfo(
                subjectDn, CertificateConstants.NO_CRL_PARTITION, false).getCrl().getRevokedCertificate(certificate));
        } else {
            assertNull("Active or Reactivated certificates must not be included in latest CRL.", crlStoreSession.getLastCRLInfo(
                    subjectDn, CertificateConstants.NO_CRL_PARTITION, false).getCrl().getRevokedCertificate(certificate));
        }
    }
    
    private void assertRevocationStatus(final X509Certificate certificate, final int revokedCertificateStatus) {
        final BigInteger serial = CertTools.getSerialNumber(certificate);
        final CertificateStatus status = certificateStoreSession.getStatus(certificate.getIssuerDN().getName(), serial);
        assertEquals(revokedCertificateStatus, status.revocationReason);
    }
    
    private static void deleteUserAndCertificates() throws Exception {
        log.trace(">deleteUserAndCertificates()");
        
        final Iterator<X509Certificate> it = certificatesToDelete.iterator();
        while (it.hasNext()) {
            internalCertificateStoreSession.removeCertificate(CertTools.getFingerprintAsString(it.next()));
        }
        certificatesToDelete.clear();
        endEntityManagementSession.deleteUser(admin, username);
        
        log.trace("<deleteUserAndCertificates()");
    }
    
    private static void deleteProfiles() throws Exception {
        log.trace(">deleteProfiles()");
        
        for (String name : endEntityProfilesToDelete) {
            endEntityProfileSession.removeEndEntityProfile(admin, name);
        }
        endEntityProfilesToDelete.clear();
        for (String name : certificateProfilesToDelete) {
            certificateProfileSession.removeCertificateProfile(admin, name);
        }        
        certificateProfilesToDelete.clear();
        
        log.trace("<deleteProfiles()");
    }
      
    private void addToCertsToDelete(final X509Certificate certificate) {
        certificatesToDelete.add(certificate);
    }
    
    private X509Certificate issueTestCertificate() throws Exception {
        final X509Certificate certificate = (X509Certificate) signSession.createCertificate(admin, username, pwd,
                new PublicKeyWrapper(KeyTools.genKeys("2048", "RSA").getPublic()));
        addToCertsToDelete(certificate);
        assertRevocationStatus(certificate, RevokedCertInfo.NOT_REVOKED);
        return certificate;
    }
    
    private void updateCertificateProfileSacc(final String name, final boolean enabled) {
        final int id = certificateProfileSession.getCertificateProfileId(name);
        final CertificateProfile profile = certificateProfileSession.getCertificateProfile(id);
        assertNotNull("Certificate profile '" + name + "' must not be null.", profile);
        profile.setSingleActiveCertificateConstraint(enabled);
        try {
            certificateProfileSession.changeCertificateProfile(admin, name, profile);
        } catch (AuthorizationDeniedException e) {
            fail("Failed to update certificate profile '" + name + "'.");
        }
    }
    
}
