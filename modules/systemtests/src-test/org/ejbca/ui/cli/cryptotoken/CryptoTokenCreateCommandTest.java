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

import static org.junit.Assert.assertNotNull;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CryptoTokenCreateCommandTest {

    private static final String CRYPTOTOKEN_NAME = CryptoTokenCreateCommandTest.class.getSimpleName();

    private final CryptoTokenCreateCommand command = new CryptoTokenCreateCommand();

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(CryptoTokenDeleteCommandTest.class.getSimpleName());

    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @After
    public void teardown() throws AuthorizationDeniedException {
        Integer cryptoTokenId = cryptoTokenManagementSession.getIdFromName(CRYPTOTOKEN_NAME);
        if (cryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
        }
    }

    @Test
    public void testCommand() {
        String[] args = new String[] { CRYPTOTOKEN_NAME, "foo123", "true", SoftCryptoToken.class.getSimpleName(), "true" };
        command.execute(args);
        assertNotNull("No crypto token was created.", cryptoTokenManagementSession.getIdFromName(CRYPTOTOKEN_NAME));
    }

}
