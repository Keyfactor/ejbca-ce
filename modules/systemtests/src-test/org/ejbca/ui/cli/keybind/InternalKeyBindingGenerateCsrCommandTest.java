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
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileNotFoundException;

import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class InternalKeyBindingGenerateCsrCommandTest {

    private static final String TESTCLASS_NAME = InternalKeyBindingGenerateCsrCommandTest.class.getSimpleName();

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            InternalKeyBindingGenerateCsrCommandTest.class.getSimpleName());

    private InternalKeyBindingGenerateCsrCommand command = new InternalKeyBindingGenerateCsrCommand();

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);

    private static X509CA x509ca = null;
    private static int cryptoTokenId;
    private File csrFile;

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
        internalKeyBindingMgmtSession.createInternalKeyBinding(authenticationToken, OcspKeyBinding.IMPLEMENTATION_ALIAS, TESTCLASS_NAME,
                InternalKeyBindingStatus.DISABLED, null, cryptoTokenId, TESTCLASS_NAME, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, null, null);
        csrFile = File.createTempFile("test", ".csr");
    }

    @After
    public void tearDown() throws AuthorizationDeniedException {
        Integer keyBindingId = internalKeyBindingMgmtSession.getIdFromName(TESTCLASS_NAME);
        if (keyBindingId != null) {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(authenticationToken, keyBindingId);
        }
        Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(TESTCLASS_NAME);
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        }
        FileTools.delete(csrFile);
    }

    @Test
    public void testGenerateCsr() throws AuthorizationDeniedException, FileNotFoundException {
        String[] args = new String[] { TESTCLASS_NAME, "--genkeypair", csrFile.getAbsolutePath() };
        command.execute(args);
        try {
            PKCS10RequestMessage msg = RequestMessageUtils.genPKCS10RequestMessage(FileTools.readFiletoBuffer(csrFile.getAbsolutePath()));
            assertEquals("Wrong DN in generated request", "CN=InternalKeyBindingGenerateCsrCommandTest", msg.getRequestDN());
        } catch (Exception e) {
            e.printStackTrace();
            fail("A correct CSR was not generated.");
        }
        args = new String[] { TESTCLASS_NAME, "--genkeypair", csrFile.getAbsolutePath(), "--subjectdn", "C=SE,O=org,CN=name", "--x500dnorder"};
        command.execute(args);
        try {
            PKCS10RequestMessage msg = RequestMessageUtils.genPKCS10RequestMessage(FileTools.readFiletoBuffer(csrFile.getAbsolutePath()));
            JcaPKCS10CertificationRequest jcareq = new JcaPKCS10CertificationRequest(msg.getCertificationRequest().getEncoded());
            assertEquals("Wring order of DN, should be X500 with C first", "C=SE,O=org,CN=name", jcareq.getSubject().toString());
        } catch (Exception e) {
            e.printStackTrace();
            fail("A correct CSR was not generated.");
        }
        args = new String[] { TESTCLASS_NAME, "--genkeypair", csrFile.getAbsolutePath(), "--subjectdn", "C=SE,O=org,CN=name"};
        command.execute(args);
        try {
            PKCS10RequestMessage msg = RequestMessageUtils.genPKCS10RequestMessage(FileTools.readFiletoBuffer(csrFile.getAbsolutePath()));
            JcaPKCS10CertificationRequest jcareq = new JcaPKCS10CertificationRequest(msg.getCertificationRequest().getEncoded());
            assertEquals("Wring order of DN, should be LDAP with CN first", "CN=name,O=org,C=SE", jcareq.getSubject().toString());
        } catch (Exception e) {
            e.printStackTrace();
            fail("A correct CSR was not generated.");
        }
    }
}
