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

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class InternalKeyBindingSetStatusCommandTest {

    private static final String TESTCLASS_NAME = InternalKeyBindingSetStatusCommandTest.class.getSimpleName();

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            InternalKeyBindingSetStatusCommandTest.class.getSimpleName());

    private InternalKeyBindingSetStatusCommand command = new InternalKeyBindingSetStatusCommand();

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);

    private static X509CA x509ca = null;
    private static int cryptoTokenId;
    private static int internalKeyBindingId;

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
        // Create a certificate (required to activate the IKB later)
        SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
        CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        EndEntityInformation endEntityInformation = new EndEntityInformation("test"+TESTCLASS_NAME, "CN=" + TESTCLASS_NAME, x509ca.getCAId(), null, null,
                new EndEntityType(EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                EndEntityConstants.TOKEN_USERGEN, 0, null);
        endEntityInformation.setPassword("foo123");
        KeyPair keyPair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        RequestMessage req = new SimpleRequestMessage(keyPair.getPublic(), endEntityInformation.getUsername(), endEntityInformation.getPassword());
        X509Certificate ocspSigningCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(
                authenticationToken, endEntityInformation, req, X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
        // Create the IKB
        internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(authenticationToken, OcspKeyBinding.IMPLEMENTATION_ALIAS,
                TESTCLASS_NAME, InternalKeyBindingStatus.DISABLED, CertTools.getFingerprintAsString(ocspSigningCertificate), cryptoTokenId, TESTCLASS_NAME, AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
                null, null);
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
    }

    @Test
    public void testSetStatus() throws AuthorizationDeniedException {
        String[] args = new String[] { TESTCLASS_NAME, InternalKeyBindingStatus.ACTIVE.name()};
        command.execute(args);
        InternalKeyBindingInfo internalKeyBindingInfo = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(authenticationToken,
                internalKeyBindingId);
        assertEquals("Correct status was not set.",  InternalKeyBindingStatus.ACTIVE, internalKeyBindingInfo.getStatus());
    }
}
