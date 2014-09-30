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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CryptoTokenActivateCommandTest {

    private static final String TOKEN_NAME = CryptoTokenActivateCommandTest.class.getSimpleName();
    private static final String TOKEN_PASSWORD = "foo123";

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(CryptoTokenDeleteCommandTest.class.getSimpleName());

    private CryptoTokenActivateCommand command = new CryptoTokenActivateCommand();
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
                cryptoTokenProperties, null, TOKEN_PASSWORD.toCharArray());
        cryptoTokenManagementSession.deactivate(authenticationToken, cryptoTokenId);
        CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
        if(cryptoTokenInfo.isAutoActivation()) {
            throw new RuntimeException("Auto activation is active on crypto token.");
        }
        if (cryptoTokenInfo.isActive()) {
            throw new RuntimeException("Crypto token is already active, test cannot continue");
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
        String[] args = new String[] { TOKEN_NAME, TOKEN_PASSWORD };
        CommandResult result = command.execute(args);
        assertEquals("Command did not succeed.", CommandResult.SUCCESS, result);
        CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
        assertTrue("Crypto token was not activated.", cryptoTokenInfo.isActive());
    }
}
