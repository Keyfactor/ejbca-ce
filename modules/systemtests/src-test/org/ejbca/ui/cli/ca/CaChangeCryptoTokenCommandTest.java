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

package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.File;
import java.io.FileWriter;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CaChangeCryptoToken
 * 
 * @version $Id$
 */
public class CaChangeCryptoTokenCommandTest {
    private final static Logger log = Logger.getLogger(CaChangeCryptoTokenCommandTest.class);

    private static final String CA_NAME = "1327changecryptotoken";
    private static final String CRYPTOTOKEN_BASENAME = "1327newcryptotoken";
    private static final String tempDir = System.getProperty("java.io.tmpdir");
    private static final String PROPERTIESFILE = tempDir + "/1327changekeystore.properties";

    private CaChangeCryptoTokenCommand caChangeCryptoTokenCommand;
    private int cryptoTokenId1;
    private int cryptoTokenId2;
    private String cryptoTokenName1;
    private String cryptoTokenName2;
    
    private AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            new UsernamePrincipal("CaChangeCryptoTokenCommandTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CryptoTokenManagementSessionRemote tokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        caChangeCryptoTokenCommand = new CaChangeCryptoTokenCommand();
        CaTestCase.removeTestCA(CA_NAME);
        CaTestCase.createTestCA(CA_NAME);
        cryptoTokenId1 = caSession.getCAInfo(authenticationToken, CA_NAME).getCAToken().getCryptoTokenId();
        cryptoTokenName1 = tokenSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId1).getName();
        log.info("First crypto token: "+cryptoTokenId1+", "+cryptoTokenName1);
        cryptoTokenId2 = CryptoTokenTestUtils.createCryptoTokenForCA(authenticationToken, CRYPTOTOKEN_BASENAME, String.valueOf(1024));
        cryptoTokenName2 = tokenSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId2).getName();
        log.info("Second crypto token: "+cryptoTokenId2+", "+cryptoTokenName2);
    }

    @After
    public void tearDown() throws Exception {
        CaTestCase.removeTestCA(CA_NAME);
        CryptoTokenTestUtils.removeCryptoToken(authenticationToken, cryptoTokenId1);
        CryptoTokenTestUtils.removeCryptoToken(authenticationToken, cryptoTokenId2);
    }

    /** Test trivial happy path for execute, i.e, change crypto tokens, and restore it again. */
    @Test
    public void testExecuteHappyPath() throws Exception {
        final String[] TEST_HAPPY_PATH_ARGS = { "--caname", CA_NAME, "--cryptotoken", cryptoTokenName2, "--tokenprop", PROPERTIESFILE};
        final String[] EXECUTE_HAPPY_PATH_ARGS = { "--caname", CA_NAME, "--cryptotoken", cryptoTokenName2, "--tokenprop", PROPERTIESFILE, "--execute"};
        final String[] EXECUTE_RESTORE_HAPPY_PATH_ARGS = { "--caname", CA_NAME, "--cryptotoken", cryptoTokenName1, "--tokenprop", PROPERTIESFILE, "--execute"};

        try {
            CAInfo info = caSession.getCAInfo(authenticationToken, CA_NAME);
            int cryptoTokenId = info.getCAToken().getCryptoTokenId();
            CryptoTokenInfo tokenInfo = tokenSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
            assertNotNull("CryptoTokenInfo of a new CA should not be null", tokenInfo);
            
            // Create a properties file
            FileWriter fw = new FileWriter(PROPERTIESFILE);
            fw.write("certSignKey signKey\n");
            fw.write("crlSignKey signKey\n");
            fw.write("defaultKey encryptKey\n");
            fw.write("testKey encryptKey\n");
            fw.close();
            
            // First we test a change, should not execute
            assertEquals(CommandResult.SUCCESS, caChangeCryptoTokenCommand.execute(TEST_HAPPY_PATH_ARGS));
            info = caSession.getCAInfo(authenticationToken, CA_NAME);
            cryptoTokenId = info.getCAToken().getCryptoTokenId();
            tokenInfo = tokenSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
            assertEquals("Crypto token id should not have changed", cryptoTokenId1, info.getCAToken().getCryptoTokenId());
            assertEquals("Crypto token name should not have changed", cryptoTokenName1, tokenInfo.getName());
            // Default properties from creating the Test CA
            assertEquals("signKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));
            assertEquals("signKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING));
            assertNull(info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING));
            assertEquals("encryptKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING));
            assertEquals(null, info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING));
            
            // Second change the crypto token
            assertEquals(CommandResult.SUCCESS, caChangeCryptoTokenCommand.execute(EXECUTE_HAPPY_PATH_ARGS));
            info = caSession.getCAInfo(authenticationToken, CA_NAME);
            cryptoTokenId = info.getCAToken().getCryptoTokenId();
            tokenInfo = tokenSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
            assertEquals("Crypto token name should have changed", cryptoTokenName2, tokenInfo.getName());
            assertEquals("Crypto token id should have changed", cryptoTokenId2, cryptoTokenId);
            assertEquals("signKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));
            assertEquals("signKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING));
            assertNull(info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING));
            assertEquals("encryptKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING));
            assertEquals("encryptKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING));

            // Third change it back again, but change keys the way around
            fw = new FileWriter(PROPERTIESFILE);
            fw.write("certSignKey encryptKey\n");
            fw.write("crlSignKey encryptKey\n");
            fw.write("defaultKey signKey\n");
            fw.write("testKey signKey\n");
            fw.write("keyEncryptKey encryptKey\n");
            fw.close();
            assertEquals(CommandResult.SUCCESS, caChangeCryptoTokenCommand.execute(EXECUTE_RESTORE_HAPPY_PATH_ARGS));
            info = caSession.getCAInfo(authenticationToken, CA_NAME);
            cryptoTokenId = info.getCAToken().getCryptoTokenId();
            tokenInfo = tokenSession.getCryptoTokenInfo(authenticationToken, cryptoTokenId);
            assertEquals("Crypto token id should have changed", cryptoTokenId1, cryptoTokenId);
            assertEquals("Crypto token name should have changed", cryptoTokenName1, tokenInfo.getName());
            assertEquals("encryptKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));
            assertEquals("encryptKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING));
            assertEquals("encryptKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING));
            assertEquals("signKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING));
            assertEquals("signKey", info.getCAToken().getProperties().getProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING));
        } finally {
            File f = new File(PROPERTIESFILE);
            f.deleteOnExit();
        }
    }

}
