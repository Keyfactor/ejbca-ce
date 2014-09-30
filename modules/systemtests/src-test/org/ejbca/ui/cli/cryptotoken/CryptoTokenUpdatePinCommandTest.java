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

import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
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
public class CryptoTokenUpdatePinCommandTest {

    private static final String TOKEN_NAME = CryptoTokenUpdatePinCommandTest.class.getSimpleName();
    private static final String TOKEN_PIN = "foo123";

    private final CryptoTokenUpdatePinCommand command = new CryptoTokenUpdatePinCommand();

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            CryptoTokenDeleteCommandTest.class.getSimpleName());

    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);

    private Integer cryptoTokenId;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(SoftCryptoToken.NODEFAULTPWD, "true");
        cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, TOKEN_NAME, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, TOKEN_PIN.toCharArray());
        cryptoTokenManagementSession.deactivate(authenticationToken, cryptoTokenId);
        CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
        if (cryptoTokenInfo.isActive()) {
            throw new RuntimeException("Crypto token is active, test cannot continue");
        }
    }

    @After
    public void teardown() throws AuthorizationDeniedException {
        Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(TOKEN_NAME);
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        }
    }

    @Test
    public void testCommand() throws AuthorizationDeniedException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException {
        final String newPin = "bar123";
        String[] args = new String[] { TOKEN_NAME, TOKEN_PIN, newPin };
        command.execute(args);
        cryptoTokenManagementSession.activate(authenticationToken, cryptoTokenId, newPin.toCharArray());
        CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
        assertTrue("Pin was apparently not replaced.", cryptoTokenInfo.isActive());
    }

}
