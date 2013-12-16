/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.Arrays;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * System tests for InternalKeyBindingCreateCommand
 * 
 * @version $Id$
 *
 */
public class InternalKeyBindingCreateCommandTest {

    private static final String TESTCLASSNAME = InternalKeyBindingCreateCommandTest.class.getSimpleName();
    private static final String KEYBINDING_NAME = "CliTest";
    private static final String KEY_PAIR_ALIAS = "CliTest";
    private static final String[] STANDARD_ARGS = { "create", KEYBINDING_NAME, "OcspKeyBinding", "DISABLED", "null", TESTCLASSNAME, KEY_PAIR_ALIAS,
            "SHA1WithRSA", "--property", "nonexistingisgood=false", "--property", "maxAge=0", "--property", "nonexistingisrevoked=true",
            "--property", "requireTrustedSignature=true", "--property", "untilNextUpdate=0", "--property", "responderidtype=NAME", "--property",
            "includecertchain=false" };
  
    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(TESTCLASSNAME));

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);

    private InternalKeyBindingCreateCommand command = new InternalKeyBindingCreateCommand();

    private static X509CA x509ca = null;
    private static int cryptoTokenId;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        x509ca = CryptoTokenTestUtils.createTestCA(alwaysAllowToken, "CN=" + TESTCLASSNAME);
        cryptoTokenId = CryptoTokenTestUtils.createCryptoToken(alwaysAllowToken, TESTCLASSNAME);
        cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, KEY_PAIR_ALIAS, "RSA2048");
    }

    @AfterClass
    public static void afterClass() throws Exception {
        cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
        if (x509ca != null) {
            final int caCryptoTokenId = caSession.getCAInfo(alwaysAllowToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, caCryptoTokenId);
            caSession.removeCA(alwaysAllowToken, x509ca.getCAId());
        }
    }

    @Test
    public void testAddVanillaKeyBinding() throws ErrorAdminCommandException, AuthorizationDeniedException {
        try {
            command.execute(STANDARD_ARGS);
            assertNotNull("No internal keybinding was created", internalKeyBindingMgmtSession.getIdFromName(KEYBINDING_NAME));
        } finally {
            Integer keyBindingId = internalKeyBindingMgmtSession.getIdFromName(KEYBINDING_NAME);
            if (keyBindingId != null) {
                internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, keyBindingId);
            }
        }
    }

    /**
     * Test adding a key binding with unknown properties, verify that the keybinding is not created.
     * 
     * Note that this test may give false positives of creation fails for any other reason.
     */
    @Test
    public void testAddUnknownProperties() throws ErrorAdminCommandException, AuthorizationDeniedException {
        try {
            String[] args = Arrays.copyOf(STANDARD_ARGS, STANDARD_ARGS.length);
            args[args.length-1] = "fakeproperty=3";
            command.execute(args);
            assertNull("No internal keybinding was created", internalKeyBindingMgmtSession.getIdFromName(KEYBINDING_NAME));
        } finally {
            Integer keyBindingId = internalKeyBindingMgmtSession.getIdFromName(KEYBINDING_NAME);
            if (keyBindingId != null) {
                internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, keyBindingId);
            }
        }
    }

    /**
     * Adds a keybinding with a property set to something it can't be cast to
     * 
     * Note that this test may give false positives of creation fails for any other reason.
     */
    @Test
    public void testAddKeyWithInvalidProperty() throws ErrorAdminCommandException, AuthorizationDeniedException {
        try {
            String[] args = Arrays.copyOf(STANDARD_ARGS, STANDARD_ARGS.length);
            args[11] = "maxAge=banana";
            command.execute(args);
            assertNull("Keybinding of invalid type was created.", internalKeyBindingMgmtSession.getIdFromName(KEYBINDING_NAME));
        } finally {
            Integer keyBindingId = internalKeyBindingMgmtSession.getIdFromName(KEYBINDING_NAME);
            if (keyBindingId != null) {
                internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, keyBindingId);
            }
        }
    }
}
