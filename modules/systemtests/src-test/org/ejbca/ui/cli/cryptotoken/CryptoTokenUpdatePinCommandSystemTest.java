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
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * @version $Id$
 *
 */
public class CryptoTokenUpdatePinCommandSystemTest {

    private static final String TOKEN_NAME = CryptoTokenUpdatePinCommandSystemTest.class.getSimpleName();
    private static final String TOKEN_PIN = "foo123";
    

    private final CryptoTokenUpdatePinCommand command = new CryptoTokenUpdatePinCommand();

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            CryptoTokenDeleteCommandSystemTest.class.getSimpleName());

    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private CryptoTokenManagementProxySessionRemote cryptoTokenProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private Integer cryptoTokenId;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, TOKEN_NAME, SoftCryptoToken.class.getName(),
                cryptoTokenProperties, null, TOKEN_PIN.toCharArray());
        cryptoTokenManagementSession.deactivate(authenticationToken, cryptoTokenId);
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
        final String updatePin = "bar123";
        String[] argsUsingOriginalOldPin = new String[] { TOKEN_NAME, TOKEN_PIN, updatePin };
        String[] argsUsingUpdatedPin = new String[] { TOKEN_NAME, updatePin, TOKEN_PIN };
        // Try to update pin using correct original pin as old pin. Should succeed.
        CommandResult commandResult = command.execute(argsUsingOriginalOldPin);
        assertTrue("Should not fail. setpin command failed using existing pin." , commandResult.equals(CommandResult.SUCCESS));
        // Try to update pin using original pin as old pin. Should fail since pin has been successfully updated with a new pin.
        CommandResult commandResultShouldFailWithOldPin = command.execute(argsUsingOriginalOldPin);        
        assertTrue("Should fail. setpin command did not fail as it should using old pin after setpin command with new pin.", commandResultShouldFailWithOldPin.equals(CommandResult.FUNCTIONAL_FAILURE));        
        // Try to update pin again using the correct recently updated pin as old pin. Should succeed.
        CommandResult commandResultShouldNotFailWithNewPin = command.execute(argsUsingUpdatedPin);
        assertTrue("Should not fail. setpin command failed authenticating with new pin and reset back to old pin.", commandResultShouldNotFailWithNewPin.equals(CommandResult.SUCCESS));
        // Given the check "if (oldAutoActivationPin != null || !updateOnly)" and a successful authentication, a new auto-activation pin will be set and
        // the cryptotoken in question should be active:
        CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
        assertTrue("Token with auto-activation should be active after update.", cryptoTokenInfo.isActive());
    }
    
    @Test
    public void testRemovePin() throws AuthorizationDeniedException, CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException {
        // Given
        String[] args = new String[] { "--token", TOKEN_NAME, "--oldpin", TOKEN_PIN, "--remove" };
        // When
        command.execute(args);
        cryptoTokenProxySession.flushCache();
        CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
        // Then
        assertFalse("Autoactivation was not removed.", cryptoTokenInfo.isAutoActivation());
    }
}
