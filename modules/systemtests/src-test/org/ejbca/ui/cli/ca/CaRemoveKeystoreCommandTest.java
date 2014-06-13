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

package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.File;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CaExportCACommand, CaRemoveKeyStoreCommand and CaRestoreKeyStoreCommand
 * 
 * @version $Id: CaEditCommandTest.java 16866 2013-05-24 07:28:12Z anatom $
 */
public class CaRemoveKeystoreCommandTest {

    private static final String CA_NAME = "1327removekeystore";
    private static final String tempDir = System.getProperty("java.io.tmpdir");
    private static final String KEYSTOREFILE = tempDir + "/1327removekeystore.p12";

    private static final String[] EXPORT_HAPPY_PATH_ARGS = { "-kspassword", "foo1234", CA_NAME, KEYSTOREFILE };
    private static final String[] REMOVE_HAPPY_PATH_ARGS = { CA_NAME };
    private static final String[] RESTORE_HAPPY_PATH_ARGS = { "-kspassword", "foo1234", CA_NAME, KEYSTOREFILE, "-s", "SignatureKeyAlias", "-e",
            "EncryptionKeyAlias" };

    private CaExportCACommand caExportCaCommand;
    private CaRemoveKeyStoreCommand caRemoveKeystoreCommand;
    private CaRestoreKeyStoreCommand caRestoreKeystoreCommand;

    private AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            new UsernamePrincipal("CaRemoveKeystoreCommandTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CryptoTokenManagementSessionRemote tokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        caExportCaCommand = new CaExportCACommand();
        caRemoveKeystoreCommand = new CaRemoveKeyStoreCommand();
        caRestoreKeystoreCommand = new CaRestoreKeyStoreCommand();
        CaTestCase.removeTestCA(CA_NAME);
        CaTestCase.createTestCA(CA_NAME);
    }

    @After
    public void tearDown() throws Exception {
        CaTestCase.removeTestCA(CA_NAME);
    }

    /** Test trivial happy path for execute, i.e, remove keystore from an ordinary, soft token CA, and restore it again. */
    @Test
    public void testExecuteHappyPath() throws Exception {
        try {
            CAInfo info = caSession.getCAInfo(authenticationToken, CA_NAME);
            int cryptoTokenId = info.getCAToken().getCryptoTokenId();
            CryptoTokenInfo tokenInfo = tokenSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
            assertNotNull("CryptoTokenInfo of a new CA should not be null", tokenInfo);
            // First we have to export the CA token keystore so we can import it back later
            assertEquals(CommandResult.SUCCESS, caExportCaCommand.execute(EXPORT_HAPPY_PATH_ARGS));
            // Second remove the keystore of the CA
            assertEquals(CommandResult.SUCCESS, caRemoveKeystoreCommand.execute(REMOVE_HAPPY_PATH_ARGS));
            info = caSession.getCAInfo(authenticationToken, CA_NAME);
            cryptoTokenId = info.getCAToken().getCryptoTokenId();
            tokenInfo = tokenSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
            assertNull("CryptoTokenInfo of a CA with removed keystore should be null", tokenInfo);
            // Third restore the keystore of the CA again
            assertEquals(CommandResult.SUCCESS, caRestoreKeystoreCommand.execute(RESTORE_HAPPY_PATH_ARGS));
            info = caSession.getCAInfo(authenticationToken, CA_NAME);
            cryptoTokenId = info.getCAToken().getCryptoTokenId();
            tokenInfo = tokenSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
            assertNotNull("CryptoTokenInfo of a CA with restored keystore should not be null", tokenInfo);
        } finally {
            File f = new File(KEYSTOREFILE);
            f.deleteOnExit();
        }
    }

}
