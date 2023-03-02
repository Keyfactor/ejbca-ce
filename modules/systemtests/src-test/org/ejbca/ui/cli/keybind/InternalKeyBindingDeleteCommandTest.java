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

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.KeyGenParams;

import static org.junit.Assert.assertNull;

/**
 * @version $Id$
 *
 */
public class InternalKeyBindingDeleteCommandTest {

    private static final String TESTCLASS_NAME = InternalKeyBindingDeleteCommandTest.class.getSimpleName();

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            InternalKeyBindingDeleteCommandTest.class.getSimpleName());

    private InternalKeyBindingDeleteCommand command = new InternalKeyBindingDeleteCommand();

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
        cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, TESTCLASS_NAME, KeyGenParams.builder("RSA2048").build());
    }

    @AfterClass
    public static void afterClass() throws Exception {
        cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        if (x509ca != null) {
            CaTestUtils.removeCa(authenticationToken, x509ca.getCAInfo());
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
        Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(TESTCLASS_NAME);
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        }
    }

    @Test
    public void testDeleteKeyBinding() throws AuthorizationDeniedException {
        String[] args = new String[] { TESTCLASS_NAME };
        command.execute(args);
        assertNull("Internal keybinding was not deleted.",
                internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindingId));
    }
}
