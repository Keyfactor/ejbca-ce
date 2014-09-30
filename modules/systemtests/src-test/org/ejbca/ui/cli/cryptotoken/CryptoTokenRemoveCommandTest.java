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
package org.ejbca.ui.cli.cryptotoken;

import static org.junit.Assert.assertFalse;

import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CryptoTokenRemoveCommandTest {

    private static final String TOKEN_NAME = CryptoTokenRemoveCommandTest.class.getSimpleName();
    private static final String KEYPAIR_ALIAS = CryptoTokenRemoveCommandTest.class.getSimpleName();

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            CryptoTokenRemoveCommandTest.class.getSimpleName());

    private CryptoTokenRemoveCommand command = new CryptoTokenRemoveCommand();
    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);

    private Integer cryptoTokenId = null;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
        cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, TOKEN_NAME, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, "foo123".toCharArray());
        cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, KEYPAIR_ALIAS, "1024");
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, KEYPAIR_ALIAS)) {
            throw new RuntimeException("No alias was created, cannot continue.");
        }
    }

    @After
    public void teardown() throws AuthorizationDeniedException {
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        }
    }

    @Test
    public void testCommand() throws AuthorizationDeniedException {
        String[] args = new String[] { TOKEN_NAME, KEYPAIR_ALIAS};
        command.execute(args);
        assertFalse("Alias was not removed", cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, KEYPAIR_ALIAS));
    }
}
