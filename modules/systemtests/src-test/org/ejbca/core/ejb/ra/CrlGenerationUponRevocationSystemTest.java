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
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.model.SecConst;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

/**
 * Tests CRL generation upon revocation (CA setting).
 */
public class CrlGenerationUponRevocationSystemTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CrlGenerationUponRevocationSystemTest.class);

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken("CrlGenerationUponRevocationSystemTest");
    private static final ArrayList<String> usernames = new ArrayList<>();

    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);

    private String username;
    private String pwd;
    private final int caId = getTestCAId();
    private final String caName = getTestCAName();
    private long deltaCrlPeriod = 0L;

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
        log.trace(">CrlGenerationUponRevocationSystemTest.setUp()");
        username = genRandomUserName();
        pwd = genRandomPwd();
        super.setUpAuthTokenAndRole(getRoleName() + "Base");
        removeTestCA(); // We can't be sure this CA was not left over from
        createTestCAWithGenerateCrlUponRevocation(deltaCrlPeriod);
        addDefaultRole();
    }

    private final boolean createTestCAWithGenerateCrlUponRevocation(final long deltaCrlPeriod) throws Exception {
        final int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(admin, caName, "2048");

        log.debug("Creating CryptoToken with ID " + cryptoTokenId + " to be used by CA " + caName);
        final CAToken caToken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        X509CAInfo caInfo = X509CAInfo.getDefaultX509CAInfo("CN=" + caName, caName, CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, caToken);
        caInfo.setDescription("JUnit RSA CA");
        caInfo.setGenerateCrlUponRevocation(true);
        caInfo.setDeltaCRLPeriod(deltaCrlPeriod);
        caInfo.setUseCRLNumber(true);
        try {
            caAdminSession.createCA(admin, caInfo);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalArgumentException("Could not create CA.", e);
        }
        caInfo = (X509CAInfo) caSession.getCAInfo(admin, caName);
        final String normalizedDN = CertTools.stringToBCDNString("CN=" + caName);
        final X509Certificate cert = (X509Certificate) caInfo.getCertificateChain().iterator().next();

        // Re-factor.
        final String normalizedCertDN = CertTools.stringToBCDNString(cert.getSubjectDN().toString());
        if (!normalizedCertDN.equals(normalizedDN)) {
            log.error("CA certificate DN is not what it should. Is '" + normalizedDN + "'. Should be '" + normalizedCertDN + "'.");
            return false;
        }
        if (!caInfo.getSubjectDN().equals(normalizedCertDN)) {
            log.error("Creating CA failed!");
            return false;
        }
        if (certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert)) == null) {
            log.error("CA certificate not available in database!!");
            return false;
        }
        assertEquals("Test CA was not active after creation.", CAConstants.CA_ACTIVE, caInfo.getStatus());
        log.trace("<createTestCA: " + caInfo.getCAId());
        return true;
    }

    @After
    public void teardown() throws Exception {
        super.tearDown();
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @Test
    public void test01RevokeCertificate() throws Exception {
        addUser();

        final KeyPair keys = KeyTools.genKeys("2048", "RSA");
        final X509Certificate certificate = (X509Certificate) signSession.createCertificate(admin, username, pwd,
                new PublicKeyWrapper(keys.getPublic()));
        final BigInteger serial = CertTools.getSerialNumber(certificate);
        final String subjectDn = CertTools.getIssuerDN(certificate);

        CertificateStatus status = certificateStoreSession.getStatus(subjectDn, serial);
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);
        int crlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, false);
        assertTrue("Initial CRL number must be 1.", crlNumber == 1);

        // Revoke the certificate, put on hold
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, serial, subjectDn);

        // Reactivate the certificate
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.NOT_REVOKED, serial, subjectDn);

        // Revoke the certificate, put on hold
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, serial, subjectDn);

        // For the following tests in sequence.
        deltaCrlPeriod = 10 * SimpleTime.MILLISECONDS_PER_HOUR;
    }

    // Tests with Delta CRLs.

    @Test
    public void test02RevokeCertificateIncludingDeltaCrls() throws Exception {
        addUser();

        final KeyPair keys = KeyTools.genKeys("2048", "RSA");
        final X509Certificate certificate = (X509Certificate) signSession.createCertificate(admin, username, pwd,
                new PublicKeyWrapper(keys.getPublic()));
        final BigInteger serial = CertTools.getSerialNumber(certificate);
        final String subjectDn = CertTools.getIssuerDN(certificate);

        CertificateStatus status = certificateStoreSession.getStatus(subjectDn, serial);
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);
        int crlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, false);
        assertTrue("Initial CRL number must be 1.", crlNumber == 1);

        // Revoke the certificate, put on hold
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, serial, subjectDn);

        // Reactivate the certificate
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.NOT_REVOKED, serial, subjectDn);

        // Revoke the certificate, put on hold
        revokeCertificateAndAssertCrlGeneration(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, serial, subjectDn);
    }

    private final void revokeCertificateAndAssertCrlGeneration(final int revocationReason, final BigInteger serial, final String subjectDn)
            throws Exception {
        final int crlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, false);
        final int deltaCrlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, true);

        endEntityManagementSession.revokeCert(admin, serial, subjectDn, revocationReason);
        final CertificateStatus status = certificateStoreSession.getStatus(subjectDn, serial);
        assertEquals(revocationReason, status.revocationReason);

        final int newCrlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, false);
        final int newDeltaCrlNumber = crlStoreSession.getLastCRLNumber(subjectDn, CertificateConstants.NO_CRL_PARTITION, true);

        assertTrue("CRL was not generated upon revocation.", newCrlNumber == crlNumber + 1);
        if (deltaCrlPeriod > 0L) {
            assertTrue("Delta CRL was not generated upon revocation.", newDeltaCrlNumber == deltaCrlNumber + 1);
        }
    }

    /**
     * Tests creation of new user and duplicate user
     * 
     * @throws Exception any exception.
     */
    private void addUser() throws Exception {
        log.trace(">addUser()");

        final String email = username + "@primekey.com";
        final EndEntityInformation eeInfo = new EndEntityInformation(username, "C=SE, O=PrimeKey, CN=" + username, caId, "rfc822name=" + email, email,
                EndEntityTypes.ENDUSER.toEndEntityType(), EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
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

}
