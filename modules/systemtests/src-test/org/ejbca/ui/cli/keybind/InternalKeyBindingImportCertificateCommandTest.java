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
package org.ejbca.ui.cli.keybind;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.ocsp.OcspTestUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * @version $Id$
 *
 */
public class InternalKeyBindingImportCertificateCommandTest {

    private static final String TESTCLASS_NAME = InternalKeyBindingImportCertificateCommandTest.class.getSimpleName();

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            InternalKeyBindingImportCertificateCommandTest.class.getSimpleName());

    private InternalKeyBindingImportCertificateCommand command = new InternalKeyBindingImportCertificateCommand();
    private InternalKeyBindingExportCertificateCommand commandexport = new InternalKeyBindingExportCertificateCommand();

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static X509CA x509ca = null;
    private static int cryptoTokenId;
    private static int internalKeyBindingId;
    private File certificateFile;
    private File certificateExportFile;
    private String certSerial;
    
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, "CN=" + TESTCLASS_NAME);
        cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(authenticationToken, TESTCLASS_NAME);
        cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, TESTCLASS_NAME, "RSA2048");

    }

    @AfterClass
    public static void afterClass() throws Exception {
        cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        if (x509ca != null) {
            final int caCryptoTokenId = caSession.getCAInfo(authenticationToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, caCryptoTokenId);
            caSession.removeCA(authenticationToken, x509ca.getCAId());
        }
    }

    @Before
    public void setup() throws Exception {
        internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(authenticationToken, OcspKeyBinding.IMPLEMENTATION_ALIAS,
                TESTCLASS_NAME, InternalKeyBindingStatus.DISABLED, null, cryptoTokenId, TESTCLASS_NAME, AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
                null, null);

    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        Integer keyBindingId = internalKeyBindingMgmtSession.getIdFromName(TESTCLASS_NAME);
        if (keyBindingId != null) {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, keyBindingId);
        }
        try {
            endEntityManagementSession.deleteUser(authenticationToken, TESTCLASS_NAME);
        } catch (Exception e) {
            //NOPMD Ignore
        }
        internalCertificateStoreSession.removeCertificatesByUsername(TESTCLASS_NAME);
    }

    @Test
    public void testImportExportCertificate()
            throws AuthorizationDeniedException, CertificateParsingException, IOException, CustomCertificateSerialNumberException,
            IllegalKeyException, CADoesntExistsException, CertificateCreateException, CryptoTokenOfflineException, SignRequestSignatureException,
            IllegalNameException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CertificateExtensionException, CertificateEncodingException {
        certificateFile = folder.newFile("testImportExportCertificate.pem");
        Certificate certificate = OcspTestUtils.createOcspSigningCertificate(authenticationToken, TESTCLASS_NAME, "C=SE,O=foo,CN=" + TESTCLASS_NAME,
                internalKeyBindingId, x509ca.getCAId());
        certSerial = CertTools.getSerialNumberAsString(certificate);
        FileOutputStream fileOutputStream = new FileOutputStream(certificateFile);
        try {
            fileOutputStream.write(CertTools.getPemFromCertificateChain(Arrays.asList(certificate)));
        } finally {
            fileOutputStream.close();
        }
        certificateExportFile = folder.newFile("testexport.pem");
        
        String[] args = new String[] { TESTCLASS_NAME, certificateFile.getAbsolutePath() };
        assertEquals("Command did not execute correctly.", CommandResult.SUCCESS, command.execute(args));
        InternalKeyBinding keyBinding = internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId);
        assertNotNull("Certificate was not imported", keyBinding.getCertificateId());
        // Now export the same cert
        String[] argsexport = new String[] { TESTCLASS_NAME, certificateExportFile.getAbsolutePath() };
        assertEquals("Command did not execute correctly.", CommandResult.SUCCESS, commandexport.execute(argsexport));
        List<Certificate> certs = CertTools.getCertsFromPEM(certificateExportFile.getAbsolutePath(), Certificate.class);
        assertEquals("One certificate should be returned", 1, certs.size());
        Certificate cert = certs.get(0);
        assertEquals("Same certificate should have been exported as was imported", certSerial, CertTools.getSerialNumberAsString(cert));
        
        
    }
    
    @Test
    public void testImportWithWrongCertificate() throws AuthorizationDeniedException, CertificateParsingException,
            CustomCertificateSerialNumberException, IllegalKeyException, CADoesntExistsException, CertificateCreateException, CesecoreException,
            CertificateExtensionException, IOException, CertificateEncodingException, InvalidAlgorithmParameterException, OperatorCreationException {
        certificateFile = folder.newFile("testImportWithWrongCertificate.pem");
        String[] args = new String[] { TESTCLASS_NAME, certificateFile.getAbsolutePath() };
        KeyPair keyPair = KeyTools.genKeys("1024", "RSA");
        int keyusage = X509KeyUsage.digitalSignature;
        final ASN1Encodable usage = KeyPurposeId.getInstance(KeyPurposeId.id_kp_OCSPSigning);
        final ASN1Sequence seq = ASN1Sequence.getInstance(new DERSequence(usage));
        Certificate certificate = CertTools.genSelfCertForPurpose("C=SE,O=foo,CN=testImportWithWrongCertificate", 365, null, keyPair.getPrivate(),
                keyPair.getPublic(), "SHA256WithRSA", false, keyusage, null, null, BouncyCastleProvider.PROVIDER_NAME, true,
                Arrays.asList(new Extension(Extension.extendedKeyUsage, true, seq.getEncoded())));           
        FileOutputStream fileOutputStream = new FileOutputStream(certificateFile);
        try {
            fileOutputStream.write(CertTools.getPemFromCertificateChain(Arrays.asList(certificate)));
        } finally {
            fileOutputStream.close();
        }
        assertEquals("Command did not execute correctly.", CommandResult.FUNCTIONAL_FAILURE, command.execute(args));
    }
}
