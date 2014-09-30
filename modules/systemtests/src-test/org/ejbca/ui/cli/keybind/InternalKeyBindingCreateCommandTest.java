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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
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
    private static final String[] STANDARD_ARGS = { KEYBINDING_NAME, "OcspKeyBinding", "DISABLED", "null", TESTCLASSNAME, KEY_PAIR_ALIAS,
            "SHA256WithRSA", "-nonexistingisgood=false", "-maxAge=0", "-nonexistingisrevoked=true", "-requireTrustedSignature=true", "-untilNextUpdate=0",
            "-responderidtype=NAME", "-includecertchain=false" };

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
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(alwaysAllowToken, "CN=" + TESTCLASSNAME);
        cryptoTokenId = CryptoTokenTestUtils.createSoftCryptoToken(alwaysAllowToken, TESTCLASSNAME);
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
    public void testAddVanillaKeyBinding() throws AuthorizationDeniedException {
        try {
            assertEquals(CommandResult.SUCCESS, command.execute(STANDARD_ARGS));
            Integer keyBindingId = internalKeyBindingMgmtSession.getIdFromName(KEYBINDING_NAME);
            assertNotNull("No internal keybinding was created", keyBindingId);
            //Verify that some non String values were correctly typed 
            InternalKeyBinding internalKeyBinding = internalKeyBindingMgmtSession.getInternalKeyBinding(alwaysAllowToken, keyBindingId);
            assertTrue("Purported Long value was not saved as Long.",
                    internalKeyBinding.getProperty(OcspKeyBinding.PROPERTY_MAX_AGE).getValue() instanceof Long);
            assertTrue("Purported Boolean value was not saved as Boolean.", internalKeyBinding.getProperty(OcspKeyBinding.PROPERTY_NON_EXISTING_GOOD)
                    .getValue() instanceof Boolean);
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
    public void testAddUnknownProperties() throws AuthorizationDeniedException {
        try {
            String[] args = Arrays.copyOf(STANDARD_ARGS, STANDARD_ARGS.length);
            args[args.length - 1] = "fakeproperty=3";
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
    public void testAddKeyWithInvalidProperty() throws AuthorizationDeniedException {
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
