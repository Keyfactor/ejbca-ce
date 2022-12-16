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
package org.ejbca.ui.cli;

import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementProxySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.CertificateSignatureException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.rules.TemporaryFolder;
import org.junit.rules.Timeout;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;

import static org.junit.Assert.assertNotNull;

/**
 * Run stress tests with ClientToolBax command Ocsp stress
 * @version $id$
 */
public class OCSPStressCommandTest {
    Ocsp command = new Ocsp();

    @Rule
    public Timeout testTimeout = new Timeout(90_000); // per test case

    private static final String END_ENTITY_PROFILE_NAME = "OCSPStressCommandTestEEP";
    private static final String CA_NAME = "OCSPStressCommandTestCA";
    private static final String DEFAULT_CA_DN = "CN=" + CA_NAME;
    private static final String PASSWORD = "foo123";
    private static final String USERNAME = "OCSPStressCommandTestUser";

    private static X509CA x509ca;
    private static String httpHost;
    private static String httpPort;
    private static String p12CertsPath;
    private static int endEntityProfileId;

    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final AuthenticationToken authToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CmpTestCommandTestAT"));
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final KeyStoreCreateSessionRemote keyStoreCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyStoreCreateSessionRemote.class);
    private final static CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);

    @BeforeClass
    public static void setUpClass() throws Exception {
        ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        httpHost = SystemTestsConfiguration.getRemoteHost(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSSERVERHOSTNAME));
        httpPort = SystemTestsConfiguration.getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));

        x509ca = CaTestUtils.createTestX509CAOptionalGenKeys(DEFAULT_CA_DN, "foo123".toCharArray(), true,
                false, "1024", X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign);
        caSession.addCA(authToken, x509ca);
        caAdminSession.publishCACertificate(authToken, x509ca.getCertificateChain(), null, x509ca.getSubjectDN());
        OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();

        final EndEntityProfile endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setAvailableCAs(Collections.singleton(x509ca.getCAId()));
        endEntityProfile.setDefaultCA(x509ca.getCAId());
        endEntityProfile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
        endEntityProfile.setReUseKeyRecoveredCertificate(true);
        endEntityProfileId = endEntityProfileSession.addEndEntityProfile(authToken, END_ENTITY_PROFILE_NAME, endEntityProfile);
    }

    @Before
    public void setUp() throws Exception {
        final File createdFolder = folder.newFolder("p12");
        p12CertsPath = createdFolder.getCanonicalPath();
    }

    @After
    public void tearDown() {
        final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
                InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        internalCertificateStoreSession.removeCertificatesByIssuer(DEFAULT_CA_DN);
        EndEntityManagementProxySessionRemote endEntityManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        endEntityManagementProxySession.deleteUsersByEndEntityProfileId(endEntityProfileId);
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
        endEntityProfileSession.removeEndEntityProfile(authToken, END_ENTITY_PROFILE_NAME);
        CaTestUtils.removeCa(authToken, x509ca.getCAInfo());
    }


    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none();
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testCommandOCSPStressTest() throws IOException, CertificateException, InvalidAlgorithmException, WaitingForApprovalException, InvalidKeySpecException, AuthStatusException, EndEntityExistsException, CustomCertificateSerialNumberException, AuthLoginException, NoSuchEndEntityException, AuthorizationDeniedException, IllegalNameException, EndEntityProfileValidationException, CADoesntExistsException, IllegalValidityException, CustomFieldException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, CryptoTokenOfflineException, CertificateRevokeException, KeyStoreException, CertificateSerialNumberException, CertificateSignatureException, ApprovalException, CertificateCreateException, IllegalKeyException, CAOfflineException {
        exit.expectSystemExitWithStatus(0);
        createUsersWithP12(1);
        File caCertificateFile = saveCaToFile();
        File serialsFile = createSerialsFile();

        int numberOfThreads = 30;
        int numberOfTests = 100;
        String waitTime = "1000";
        String httpReqPath = "http://" + httpHost + ":" + httpPort + "/ejbca/publicweb/status/ocsp";

        //OCSP stress http://ca:8080/ejbca/publicweb/status/ocsp serials.txt CMPCA.cacert.pem 30:100 1000 GET keys/tester-0.p12 foo123
        String[] args = new String[]{"OCSP", "stress", httpReqPath, serialsFile.getCanonicalPath(), caCertificateFile.getCanonicalPath(),
                numberOfThreads + ":" + numberOfTests, waitTime, "GET",
                p12CertsPath + "/" + USERNAME + 0 + ".p12", PASSWORD};
        command.execute(args);
    }

    /** Creates serials.txt with a hexadecimal and decimal serial (both non-existent */
    private File createSerialsFile() throws IOException {
        final String serials = "# This is a comment\n" +
                "0x1234567890ABCDEF1234567890ABCDEF\n" +
                "12345678901234567890\n";
        File serialsFile = folder.newFile("serials.txt");
        try (FileOutputStream fileOutputStream = new FileOutputStream(serialsFile)) {
            fileOutputStream.write(serials.getBytes(StandardCharsets.US_ASCII));
        }
        return serialsFile;
    }

    private File saveCaToFile() throws IOException, CertificateEncodingException {
        Certificate caCertificate = x509ca.getCACertificate();
        File caCertificateFile = folder.newFile("ca.pem");
        try (FileOutputStream fileOutputStream = new FileOutputStream(caCertificateFile)) {
            fileOutputStream.write(CertTools.getPemFromCertificateChain(Collections.singletonList(caCertificate)));
        }
        return caCertificateFile;
    }

    private void createUsersWithP12(int number) throws EndEntityExistsException, WaitingForApprovalException, CertificateSerialNumberException, CADoesntExistsException, EndEntityProfileValidationException, AuthorizationDeniedException, IllegalNameException, CustomFieldException, ApprovalException, NoSuchEndEntityException, AuthLoginException, IllegalKeyException, CertificateCreateException, CAOfflineException, CertificateRevokeException, NoSuchAlgorithmException, CustomCertificateSerialNumberException, CertificateSignatureException, IllegalValidityException, InvalidAlgorithmParameterException, KeyStoreException, InvalidAlgorithmException, AuthStatusException, CryptoTokenOfflineException, CertificateException, InvalidKeySpecException, IOException {
        for (int i = 0; i < number; i++) {
            String name = USERNAME + i;
            EndEntityInformation eeinfo = new EndEntityInformation(name, "CN=" + name,
                    x509ca.getCAId(), "", null, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                    endEntityProfileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
            eeinfo.setPassword("foo123");
            endEntityManagementSession.addUser(authToken, eeinfo, false);
            endEntityManagementSession.setPassword(authToken, name, "foo123");
            eeinfo = endEntityAccessSession.findUser(authToken, name);
            assertNotNull("Could not find test user", name);
            eeinfo.setPassword(PASSWORD);

            final byte[] ks1 = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(authToken,
                    name, PASSWORD, x509ca.getCAId(), "2048", AlgorithmConstants.KEYALGORITHM_RSA, SecConst.TOKEN_SOFT_P12,
                    false, true,
                    true, endEntityProfileId);

            String filename = p12CertsPath + "/" + name + ".p12";
            FileOutputStream fileOutputStream = new FileOutputStream(filename);
            fileOutputStream.write(ks1);
            fileOutputStream.close();
        }
    }
}
