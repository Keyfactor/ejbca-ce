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
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

/**
 * @version $Id$
 *
 */
public class CryptoTokenDeactivateCommandSystemTest {

    private static final String TOKEN_NAME = CryptoTokenDeactivateCommandSystemTest.class.getSimpleName();

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(CryptoTokenDeleteCommandSystemTest.class.getSimpleName());

    private CryptoTokenDeactivateCommand command = new CryptoTokenDeactivateCommand();
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
        cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, TOKEN_NAME, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, "foo123".toCharArray());
        CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
        if (!cryptoTokenInfo.isActive()) {
            throw new RuntimeException("Crypto token was not active, test cannot continue");
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
        String[] args = new String[] { TOKEN_NAME};
        command.execute(args);
        CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
        assertFalse("Crypto token was not deactivated.", cryptoTokenInfo.isActive());
    }
}
