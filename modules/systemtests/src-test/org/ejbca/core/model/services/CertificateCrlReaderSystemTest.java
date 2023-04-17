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
import static org.junit.Assert.assertFalse;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCrlStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignProxySessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.services.actions.NoAction;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.CertificateCrlReader;
import org.ejbca.scp.publisher.ScpContainer;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.TestRule;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;

/**
 * System test for the CertificateCrlReader Worker.
 * 
 * @version $Id$
 */
public class CertificateCrlReaderSystemTest {

    private static final Logger log = Logger.getLogger(CertificateCrlReaderSystemTest.class);

    private static final AuthenticationToken ADMIN_AUTHENTICATION_TOKEN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UserPasswordExpireTest"));
    private static final String ISSUER_DN = "CN=certificateCrlReaderSystemTest";
    private static final String END_ENTITY_USER = "CertificateCrlReaderSystemTestUser";
    private static final String END_ENTITY_SUBJECT_DN = "CN=" + END_ENTITY_USER;
    private static KeyPair KEY_PAIR;
    // EJBs
    private final static EjbRemoteHelper ejbRemoteHelper = EjbRemoteHelper.INSTANCE;
    private final CAAdminSessionRemote caAdminSession = ejbRemoteHelper.getRemoteSession(CAAdminSessionRemote.class);
    private final static CaSessionRemote caSession = ejbRemoteHelper.getRemoteSession(CaSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = ejbRemoteHelper.getRemoteSession(CertificateStoreSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = ejbRemoteHelper.getRemoteSession(CertificateCreateSessionRemote.class);
    private final CrlStoreSessionRemote crlStoreSession = ejbRemoteHelper.getRemoteSession(CrlStoreSessionRemote.class);
    private final CryptoTokenManagementProxySessionRemote cryptoTokenManagementSession = ejbRemoteHelper.getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final EndEntityAccessSessionRemote endEntityAccessSession = ejbRemoteHelper.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = ejbRemoteHelper.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = ejbRemoteHelper.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final InternalCrlStoreSessionRemote internalCrlStoreSession = ejbRemoteHelper.getRemoteSession(InternalCrlStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final ServiceSessionRemote serviceSession = ejbRemoteHelper.getRemoteSession(ServiceSessionRemote.class);
    private final SignSessionRemote signSession = ejbRemoteHelper.getRemoteSession(SignSessionRemote.class);
    private final SignProxySessionRemote signProxySession = ejbRemoteHelper.getRemoteSession(SignProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    /** Time to wait for operations like certificate import, file deletion etc., before considering the test to have failed. Milliseconds */
    private static final long WAIT_TIME = 30_000;
    /** Sleep time in loop iterations to avoid causing too much CPU usage. Milliseconds */
    private static final long IMPORT_ITERATION_SLEEP = 1_000;
    private static final long DELETE_ITERATION_SLEEP = 1_000;
    //
    private static X509CA testCa = null;
    private CryptoToken cryptoToken = null;
    private Certificate userCertificate = null;
    private Date currentDate = null;
    private EndEntityInformation endEntityInformation = null;
    private String serviceName = null;
    private File exchangeFolder = null;
    private String removeCrlIssuerDn = null;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        KEY_PAIR = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        // Create an issuing CA
        testCa = CaTestUtils.createTestX509CA(ISSUER_DN, null, false);
        caSession.addCA(ADMIN_AUTHENTICATION_TOKEN, testCa);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        // Remove testCa
        if(testCa != null) {
            CaTestUtils.removeCa(ADMIN_AUTHENTICATION_TOKEN, testCa.getCAInfo());
        }
    }

    @Before
    public void setUp() throws Exception {
        // Get CryptoToken
        cryptoToken = cryptoTokenManagementSession.getCryptoToken(testCa.getCAToken().getCryptoTokenId());
        // Init date
        currentDate = new Date();
        // Generate certificate
        endEntityInformation = new EndEntityInformation(
                END_ENTITY_USER,
                END_ENTITY_SUBJECT_DN,
                testCa.getCAId(),
                null,
                null,
                EndEntityTypes.ENDUSER.toEndEntityType(),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM,
                null
        );
        endEntityInformation.setPassword("foo123");
        final CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        userCertificate = testCa.generateCertificate(
                cryptoToken,
                endEntityInformation,
                KEY_PAIR.getPublic(),
                0,
                null,
                "10d",
                certificateProfile,
                "00000",
                null);
        // Set temporary folder
        exchangeFolder = folder.newFolder();
        if (!exchangeFolder.setReadable(true, false) || !exchangeFolder.setWritable(true, false)) {
            log.info("Can't changes file access mode for test folder " + exchangeFolder.getAbsolutePath() + " (expected on Windows)");
        }
    }

    @After
    public void tearDown() throws Exception {
        if(userCertificate != null) {
             internalCertificateStoreSession.removeCertificate(CertTools.getSerialNumber(userCertificate));
        }
        if(serviceName != null) {
            serviceSession.removeService(ADMIN_AUTHENTICATION_TOKEN, serviceName);
        }
        if(removeCrlIssuerDn != null) {
            internalCrlStoreSession.removeCrl(removeCrlIssuerDn);
        }
        if (endEntityAccessSession.findUser(ADMIN_AUTHENTICATION_TOKEN, END_ENTITY_USER) != null) {
            endEntityManagementSession.deleteUser(ADMIN_AUTHENTICATION_TOKEN, END_ENTITY_USER);
        }
    }

    /**
     * This test will write a certificate to a temporary file area and then use the CertificateCrlReader within service to import it to the system.
     */
    @Test
    public void readCertificateFromDisk() throws Exception {
        log.trace(">readCertificateFromDisk");
        // given
        serviceName = "readCertificateFromDisk";
        final ScpContainer activeCertificate = new ScpContainer()
                .setCertificate(userCertificate)
                .setIssuer(ISSUER_DN)
                .setUsername("testReadCertificateFromDisk")
                .setCertificateType(CertificateConstants.CERTTYPE_ENDENTITY)
                // Use fixed number
                .setCertificateProfile(4711)
                .setUpdateTime(currentDate.getTime())
                .setSerialNumber(CertTools.getSerialNumber(userCertificate))
                .setRevocationDate(0)
                .setRevocationReason(RevocationReasons.NOT_REVOKED.getDatabaseValue())
                .setCertificateStatus(CertificateConstants.CERT_ACTIVE);
        addServiceAndActivateItsTimer(getServiceConfig(CertificateCrlReader.CERTIFICATE_DIRECTORY_KEY, exchangeFolder, -1));
        final File activeCertificateFile = new File(exchangeFolder, "activeCertificateFile");

        // when
        // Write an active certificate to disk in order to simulate publishing a non-anonymous scp publishing
        FileUtils.writeByteArrayToFile(activeCertificateFile, activeCertificate.getEncoded());

        // then
        // Verify that the certificate gets read from disk
        assertFalse("Certificate was not scanned by service", waitForCertificateToBeImportedFailed(ISSUER_DN, userCertificate));
        // Verify that the CRL has been removed from the folder
        assertFalse("Certificate file was not removed after being scanned.", waitForFileDeletionFailed(activeCertificateFile));
        log.trace("<readCertificateFromDisk");
    }
    
    /**
     * Verify that an alredy written certificate can be revoked, i.e. overwritten
     */
    @Test
    public void updateCertificateFromDisk() throws Exception {
        serviceName = "updateCertificateFromDisk";
        final String username = "updateCertificateFromDisk";
        //Store a certificate manually
        certificateStoreSession.storeCertificateRemote(ADMIN_AUTHENTICATION_TOKEN, EJBTools.wrap(userCertificate), username, "1234",
                CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.NO_END_ENTITY_PROFILE, CertificateConstants.NO_CRL_PARTITION, null, new Date().getTime(), null);
        if (null == certificateStoreSession.getCertificateDataByIssuerAndSerno(ISSUER_DN, CertTools.getSerialNumber(userCertificate))) {
            throw new IllegalStateException("Certificate was not stored, cannot continue.");
        }
        //Same cert, but revoked. 
        final ScpContainer revokedCertificate = new ScpContainer().setCertificate(userCertificate).setIssuer(ISSUER_DN).setUsername(username)
                .setCertificateType(CertificateConstants.CERTTYPE_ENDENTITY)
                // Use fixed number
                .setCertificateProfile(4711).setUpdateTime(currentDate.getTime()).setSerialNumber(CertTools.getSerialNumber(userCertificate))
                .setRevocationDate(new Date().getTime()).setRevocationReason(RevocationReasons.CACOMPROMISE.getDatabaseValue())
                .setCertificateStatus(CertificateConstants.CERT_REVOKED);
        addServiceAndActivateItsTimer(getServiceConfig(CertificateCrlReader.CERTIFICATE_DIRECTORY_KEY, exchangeFolder, -1));
        final File revokedCertificateFile = new File(exchangeFolder, "revokedCertificateFile");
        FileUtils.writeByteArrayToFile(revokedCertificateFile, revokedCertificate.getEncoded());
        // Verify that the certificate gets read from disk
        assertFalse("Certificate was not scanned by service",
                waitForCertificateToBeImportedFailed(ISSUER_DN, userCertificate, CertificateStatus.REVOKED));
        // Verify that the CRL has been removed from the folder
        assertFalse("Certificate file was not removed after being scanned.", waitForFileDeletionFailed(revokedCertificateFile));
    }
    

    /**
     * Verify that an alredy written certificate can be revoked, i.e. overwritten, but this time overwriting a standard certificate with a limited 
     * dito. Regression test for ECA-10811
     */
    @Test
    public void updateFromDiskWithLimitedCertificate() throws Exception {
        serviceName = "updateFromDiskWithLimitedCertificate";
        final String username = "updateFromDiskWithLimitedCertificate";
        //Store a certificate manually
        certificateStoreSession.storeCertificateRemote(ADMIN_AUTHENTICATION_TOKEN, EJBTools.wrap(userCertificate), username, "1234",
                CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.NO_END_ENTITY_PROFILE, CertificateConstants.NO_CRL_PARTITION, null, new Date().getTime(), null);
        if (null == certificateStoreSession.getCertificateDataByIssuerAndSerno(ISSUER_DN, CertTools.getSerialNumber(userCertificate))) {
            throw new IllegalStateException("Certificate was not stored, cannot continue.");
        }  
        
        final ScpContainer revokedCertificate = new ScpContainer()
                .setIssuer(ISSUER_DN)
                .setUsername(END_ENTITY_USER)
                .setCertificateType(CertificateConstants.CERTTYPE_ENDENTITY)
                // Use fixed number
                .setCertificateProfile(4711)
                .setUpdateTime(currentDate.getTime())
                .setSerialNumber(CertTools.getSerialNumber(userCertificate))
                .setRevocationDate(new Date().getTime())
                .setRevocationReason(RevocationReasons.CACOMPROMISE.getDatabaseValue())
                .setCertificateStatus(CertificateConstants.CERT_REVOKED);
        addServiceAndActivateItsTimer(getServiceConfig(CertificateCrlReader.CERTIFICATE_DIRECTORY_KEY, exchangeFolder, -1));
        final File revokedCertificateFile = new File(exchangeFolder, "revokedCertificateFile");
        FileUtils.writeByteArrayToFile(revokedCertificateFile, revokedCertificate.getEncoded());
        // Verify that the certificate gets read from disk
        assertFalse("Certificate was not scanned by service",
                waitForCertificateToBeImportedFailed(ISSUER_DN, userCertificate, CertificateStatus.REVOKED));
        // Verify that the CRL has been removed from the folder
        assertFalse("Certificate file was not removed after being scanned.", waitForFileDeletionFailed(revokedCertificateFile));
    }
    
    /**
     * This test will write a certificate to a temporary file area and then use the CertificateCrlReader within service to import it to the system. 
     * The certificate is going to be signed by a self signed CA. 
     */
    @Test
    public void readSignedCertificateFromDisk() throws Exception {
        serviceName = "readSignedCertificateFromDisk";
       
        
        final ScpContainer activeCertificate = new ScpContainer()
                .setCertificate(userCertificate)
                .setIssuer(ISSUER_DN)
                .setUsername("testReadCertificateFromDisk")
                .setCertificateType(CertificateConstants.CERTTYPE_ENDENTITY)
                // Use fixed number
                .setCertificateProfile(4711)
                .setUpdateTime(currentDate.getTime())
                .setSerialNumber(CertTools.getSerialNumber(userCertificate))
                .setRevocationDate(0)
                .setRevocationReason(RevocationReasons.NOT_REVOKED.getDatabaseValue())
                .setCertificateStatus(CertificateConstants.CERT_ACTIVE);
        addServiceAndActivateItsTimer(getServiceConfig(CertificateCrlReader.CERTIFICATE_DIRECTORY_KEY, exchangeFolder, testCa.getCAId()));
        final File activeCertificateFile = new File(exchangeFolder, "activeCertificateFile");

        byte[] signedBytes =  signProxySession.signPayload(activeCertificate.getEncoded(), testCa.getCAId());

        // Write an active certificate to disk in order to simulate publishing a non-anonymous scp publishing
        FileUtils.writeByteArrayToFile(activeCertificateFile, signedBytes);

        // Verify that the certificate gets read from disk
        assertFalse("Certificate was not scanned by service", waitForCertificateToBeImportedFailed(ISSUER_DN, userCertificate));
        // Verify that the CRL has been removed from the folder
        assertFalse("Certificate file was not removed after being scanned.", waitForFileDeletionFailed(activeCertificateFile));
    }
    
    /**
     * Similar to the test above, but this time the certificate is going to be signed by a subca – written as a regression test. 
     */
    @Test
    public void readSignedCertificateFromFromSubCaFromDisk() throws Exception {
        serviceName = "readCertificateFromDisk";
        final String subCaDn = "CN=readSignedCertificateFromFromSubCaFromDisk";
        final X509CA subCa = CaTestUtils.createTestX509CA(subCaDn, null, SoftCryptoToken.class.getName(), testCa.getCAId(),
                X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        
        caAdminSession.createCA(ADMIN_AUTHENTICATION_TOKEN, subCa.getCAInfo());
        assertEquals("Sub CA was not created.", 2, caSession.getCAInfo(ADMIN_AUTHENTICATION_TOKEN, subCa.getCAId()).getCertificateChain().size());
      
        final ScpContainer activeCertificate = new ScpContainer().setCertificate(userCertificate).setIssuer(ISSUER_DN)
                .setUsername("testReadCertificateFromDisk").setCertificateType(CertificateConstants.CERTTYPE_ENDENTITY)
                // Use fixed number
                .setCertificateProfile(4711).setUpdateTime(currentDate.getTime()).setSerialNumber(CertTools.getSerialNumber(userCertificate))
                .setRevocationDate(0).setRevocationReason(RevocationReasons.NOT_REVOKED.getDatabaseValue())
                .setCertificateStatus(CertificateConstants.CERT_ACTIVE);
        try {
            //This time set the sub ca as verifier
            addServiceAndActivateItsTimer(getServiceConfig(CertificateCrlReader.CERTIFICATE_DIRECTORY_KEY, exchangeFolder, subCa.getCAId()));
            final File activeCertificateFile = new File(exchangeFolder, "activeCertificateFile");

            //set the sub ca as signer
            byte[] signedBytes = signProxySession.signPayload(activeCertificate.getEncoded(), subCa.getCAId());

            // Write an active certificate to disk in order to simulate publishing a non-anonymous scp publishing
            FileUtils.writeByteArrayToFile(activeCertificateFile, signedBytes);

            // Verify that the certificate gets read from disk
            assertFalse("Certificate was not scanned by service", waitForCertificateToBeImportedFailed(ISSUER_DN, userCertificate));
            // Verify that the CRL has been removed from the folder
            assertFalse("Certificate file was not removed after being scanned.", waitForFileDeletionFailed(activeCertificateFile));
        } finally {
            CaTestUtils.removeCa(ADMIN_AUTHENTICATION_TOKEN, subCa.getCAInfo());
        }
    }

    /**
     * This test will write a revoked certificate to a temporary file area and then use the CertificateCrlReader within service to import it to the system.
     */
    @Test
    public void readRevokedCertificateFromDisk() throws Exception {
        log.trace(">readRevokedCertificateFromDisk");
        // given
        createAndPersistCertificate();
        serviceName = "readRevokedCertificateFromDisk";
        // Updating with the revoked status (thereby using the other publishing variant)
        final ScpContainer revokedCertificate = new ScpContainer()
                .setCertificate(userCertificate)
                .setIssuer(ISSUER_DN)
                .setSerialNumber(CertTools.getSerialNumber(userCertificate))
                .setRevocationDate(0)
                .setRevocationReason(RevocationReasons.KEYCOMPROMISE.getDatabaseValue())
                .setCertificateStatus(CertificateConstants.CERT_REVOKED);
        addServiceAndActivateItsTimer(getServiceConfig(CertificateCrlReader.CERTIFICATE_DIRECTORY_KEY, exchangeFolder, -1));
        final File revokedCertificateFile = new File(exchangeFolder, "revokedCertificateFile");

        // when
        FileUtils.writeByteArrayToFile(revokedCertificateFile, revokedCertificate.getEncoded());

        // then
        // Verify that the certificate gets read from disk
        assertFalse("Certificate was not revoked", waitForCertificateToBeImportedFailed(ISSUER_DN, userCertificate, CertificateStatus.REVOKED));
        // Verify that the certificate gets removed from the folder
        assertFalse("Certificate file was not removed after being scanned.", waitForFileDeletionFailed(revokedCertificateFile));
        log.trace("<readRevokedCertificateFromDisk");
    }

    /**
     * This test will write a limited (obfuscated) certificate to a temporary file area and then use the CertificateCrlReader within service to import it to the system.
     */
    @Test
    public void readLimitedCertificateFromDisk() throws Exception {
        log.trace(">readLimitedCertificateFromDisk");
        // given
        serviceName = "readLimitedCertificateFromDisk";
        final ScpContainer activeCertificate = new ScpContainer()
                .setIssuer(ISSUER_DN)
                .setUsername(END_ENTITY_USER)
                .setCertificateType(CertificateConstants.CERTTYPE_ENDENTITY)
                // Use fixed number
                .setCertificateProfile(4711)
                .setUpdateTime(currentDate.getTime())
                .setSerialNumber(CertTools.getSerialNumber(userCertificate))
                .setRevocationDate(0)
                .setRevocationReason(RevocationReasons.NOT_REVOKED.getDatabaseValue())
                .setCertificateStatus(CertificateConstants.CERT_ACTIVE);
        addServiceAndActivateItsTimer(getServiceConfig(CertificateCrlReader.CERTIFICATE_DIRECTORY_KEY, exchangeFolder, -1));
        final File activeCertificateFile = new File(exchangeFolder, "activeCertificateFile");

        // when
        // Write an active certificate to disk in order to simulate publishing a non-anonymous scp publishing
        FileUtils.writeByteArrayToFile(activeCertificateFile, activeCertificate.getEncoded());

        // then
        // Verify that the certificate gets read from disk
        assertFalse("Certificate was not scanned by service", waitForCertificateToBeImportedFailed(ISSUER_DN, userCertificate));
        // Verify that the CRL has been removed from the folder
        assertFalse("Certificate file was not removed after being scanned.", waitForFileDeletionFailed(activeCertificateFile));
        log.trace("<readLimitedCertificateFromDisk");
    }

    /**
     * This test will write a revoked limited (obfuscated) certificate to a temporary file area and then use the CertificateCrlReader within service to import it to the system.
     */
    @Test
    public void readRevokedLimitedCertificateFromDisk() throws Exception {
        log.trace(">readRevokedLimitedCertificateFromDisk");
        // given
        serviceName = "readRevokedLimitedCertificateFromDisk";
        // Updating with the revoked status (thereby using the other publishing variant)
        final ScpContainer revokedCertificate = new ScpContainer()
                .setIssuer(ISSUER_DN)
                .setSerialNumber(CertTools.getSerialNumber(userCertificate))
                .setRevocationDate(0)
                .setRevocationReason(RevocationReasons.KEYCOMPROMISE.getDatabaseValue())
                .setCertificateStatus(CertificateConstants.CERT_REVOKED);
        addServiceAndActivateItsTimer(getServiceConfig(CertificateCrlReader.CERTIFICATE_DIRECTORY_KEY, exchangeFolder, -1));
        final File revokedCertificateFile = new File(exchangeFolder, "revokedCertificateFile");

        // when
        FileUtils.writeByteArrayToFile(revokedCertificateFile, revokedCertificate.getEncoded());

        // then
        // Verify that the certificate gets read from disk
        assertFalse("Certificate was not revoked", waitForCertificateToBeImportedFailed(ISSUER_DN, userCertificate, CertificateStatus.REVOKED));
        // Verify that the certificate gets removed from the folder
        assertFalse("Certificate file was not removed after being scanned.", waitForFileDeletionFailed(revokedCertificateFile));
        log.trace(">readRevokedLimitedCertificateFromDisk");
    }

    /**
     * This test will write a CRL to a temporary file area and then use the CertificateCrlReader within service to import it to the system.
     */
    @Test
    public void readCrlFromDisk() throws Exception {
        log.trace(">readCrlFromDisk");
        // given
        removeCrlIssuerDn = ISSUER_DN;
        serviceName = "readCrlFromDisk";
        final Date notAfterDate = CertTools.getNotAfter(userCertificate);
        final List<RevokedCertInfo> revokedCertInfos = Collections.singletonList(
                new RevokedCertInfo(
                        CertTools.getFingerprintAsString(userCertificate).getBytes(),
                        CertTools.getSerialNumber(userCertificate).toByteArray(),
                        currentDate.getTime(),
                        RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD,
                        (notAfterDate == null ? Long.MAX_VALUE : notAfterDate.getTime())
                )
        );
        final int crlNumber = 1337;
        final X509CRLHolder x509crlHolder = testCa.generateCRL(cryptoToken, CertificateConstants.NO_CRL_PARTITION, revokedCertInfos, crlNumber, null);
        final X509CRL crl = CertTools.getCRLfromByteArray(x509crlHolder.getEncoded());
        addServiceAndActivateItsTimer(getServiceConfig(CertificateCrlReader.CRL_DIRECTORY_KEY, exchangeFolder, -1));
        final File crlFile = new File(exchangeFolder, "canned.crl");

        // when
        // Write CRL to disk
        FileUtils.writeByteArrayToFile(crlFile, crl.getEncoded());

        // then
        // Verify that the certificate gets read from disk
        assertFalse("CRL was not scanned by service", waitForCrlToBeImportedFailed(ISSUER_DN, crlNumber));
        // Verify that the CRL gets removed from the folder
        assertFalse("CRL file was not removed after being scanned.", waitForFileDeletionFailed(crlFile));
        log.trace("<readCrlFromDisk");
    }

    private void addServiceAndActivateItsTimer(final ServiceConfiguration config) throws ServiceExistsException {
        serviceSession.addService(ADMIN_AUTHENTICATION_TOKEN, serviceName, config);
        serviceSession.activateServiceTimer(ADMIN_AUTHENTICATION_TOKEN, serviceName);
    }

    private void createAndPersistCertificate() throws Exception {
        endEntityManagementSession.addUser(ADMIN_AUTHENTICATION_TOKEN, endEntityInformation, false);
        final SimpleRequestMessage simpleRequestMessage = new SimpleRequestMessage(KEY_PAIR.getPublic(), endEntityInformation.getUsername(), endEntityInformation.getPassword());
        userCertificate = certificateCreateSession.createCertificate(
                ADMIN_AUTHENTICATION_TOKEN,
                endEntityInformation,
                simpleRequestMessage,
                X509ResponseMessage.class,
                signSession.fetchCertGenParams())
                .getCertificate();
    }

    /**
     * Wait for certificate import failure. Expected status is 'Active'.
     * @return false if it was imported, true otherwise.
     */
    private boolean waitForCertificateToBeImportedFailed(final String issuerDn, final Certificate userCertificate) throws InterruptedException {
        return waitForCertificateToBeImportedFailed(issuerDn, userCertificate, CertificateStatus.OK);
    }
    
    
    /**
     * Wait for certificate import failure.
     * @return false if it was imported, true otherwise.
     */
    private boolean waitForCertificateToBeImportedFailed(final String issuerDn, final Certificate userCertificate, final CertificateStatus expectedStatus) throws InterruptedException {
        final long startTime = System.currentTimeMillis();
        final BigInteger serialNumber = CertTools.getSerialNumber(userCertificate);
        while (System.currentTimeMillis() < startTime + WAIT_TIME) {
            // Look for CertificateDataWrapper to support limited (obfuscated) certificates without Certificate
            final CertificateDataWrapper certificateDataWrapper = certificateStoreSession.getCertificateDataByIssuerAndSerno(issuerDn, serialNumber);
            if (certificateDataWrapper != null && certificateStoreSession.getStatus(issuerDn, serialNumber).equals(expectedStatus)) {
                log.debug("Certificate found after " + (System.currentTimeMillis() - startTime) + " ms");            
                return false; // cert has been imported now
            }
            Thread.sleep(IMPORT_ITERATION_SLEEP);
        }
        log.debug("Timed out waiting for certificate to be imported");
        return true; // timeout after 30 seconds
    }

    /**
     * Wait for CRL import failure.
     * @return false if it was imported, true otherwise.
     */
    private boolean waitForCrlToBeImportedFailed(final String issuerDn, final int crlNumber) throws InterruptedException {
        final long startTime = System.currentTimeMillis();
        while (System.currentTimeMillis() < startTime + WAIT_TIME) {
            final byte[] crl = crlStoreSession.getCRL(issuerDn, CertificateConstants.NO_CRL_PARTITION, crlNumber);
            if (crl != null) {
                log.debug("CRL found after " + (System.currentTimeMillis() - startTime) + " ms");
                return false; // CRL has been imported now
            }
            Thread.sleep(IMPORT_ITERATION_SLEEP);
        }
        log.debug("Timed out waiting for CRL to be imported");
        return true; // timeout after 30 seconds
    }

    /**
     * Wait for file deletion failure.
     * @return false if it was deleted, true otherwise.
     */
    private boolean waitForFileDeletionFailed(final File file) throws InterruptedException {
        final long startTime = System.currentTimeMillis();
        while (System.currentTimeMillis() < startTime + WAIT_TIME) {
            if (!file.exists()) {
                log.debug("File deleted after " + (System.currentTimeMillis() - startTime) + " ms");
                return false; // CRL has been imported now
            }
            Thread.sleep(DELETE_ITERATION_SLEEP);
        }
        log.debug("Timed out waiting for file to be deleted");
        return true; // timeout after 30 seconds
    }

    private ServiceConfiguration getServiceConfig(final String directoryType, final File folder, int signingCaId) {
        final ServiceConfiguration config = new ServiceConfiguration();
        config.setActive(true);
        config.setDescription("CertificateCrlReaderSystemTest");
        // No mail sending for this test service
        config.setActionClassPath(NoAction.class.getName());
        config.setActionProperties(null);
        // Run the service every second
        config.setIntervalClassPath(PeriodicalInterval.class.getName());
        final Properties intervalProperties = new Properties();
        intervalProperties.setProperty(PeriodicalInterval.PROP_VALUE, "3");
        intervalProperties.setProperty(PeriodicalInterval.PROP_UNIT, PeriodicalInterval.UNIT_SECONDS);
        config.setIntervalProperties(intervalProperties);
        // Set input folder
        config.setWorkerClassPath(CertificateCrlReader.class.getName());
        final Properties workerProperties = new Properties();
        workerProperties.setProperty(directoryType, folder.getAbsolutePath());
        workerProperties.setProperty(CertificateCrlReader.SIGNING_CA_ID_KEY, Integer.toString(signingCaId));
        config.setWorkerProperties(workerProperties);
        return config;
    }
}
