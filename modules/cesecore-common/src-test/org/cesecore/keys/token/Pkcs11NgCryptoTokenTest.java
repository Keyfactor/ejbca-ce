/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.util.Properties;

import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken;
import org.cesecore.keys.token.p11ng.provider.JackNJI11Provider;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

/**
 * Test class for Pkcs11Ng functions.
 * 
 * @version $Id$
 *
 */
public class Pkcs11NgCryptoTokenTest extends CryptoTokenTestBase {

    CryptoToken token = null;
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void checkPkcs11DriverAvailable() {
        // Skip test if no PKCS11 driver is installed
        assumeTrue(PKCS11TestUtils.getHSMLibrary() != null);
        assumeTrue(PKCS11TestUtils.getHSMProvider() != null);
    }

    @After
    public void tearDown() {
        // Make sure we remove the provider after one test, so it is not still there affecting the next test
        Security.removeProvider(getProvider());
        token.deactivate();
    }
    
    @Test
    public void testCryptoTokenRSA() throws Exception {
        token = createPkcs11NgToken();
        doCryptoTokenRSA(token);
    }
    
    @Test
    public void testCryptoTokenECC() throws Exception {
        token = createPkcs11NgToken();
        doCryptoTokenECC(token, "secp256r1", 256, "secp384r1", 384);
    }
    
    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testCryptoTokenDSA() throws Exception {
        token = createPkcs11NgToken();
        doCryptoTokenDSA(token);
    }
    
    private static CryptoToken createPkcs11NgToken() throws NoSuchSlotException {
        return createPkcs11NgTokenWithAttributesFile(null, null, true);
    }
    
    private static CryptoToken createPkcs11NgTokenWithAttributesFile(String file, String tokenName, boolean extractable) throws NoSuchSlotException {
        Properties prop = new Properties();
        String hsmlib = PKCS11TestUtils.getHSMLibrary();
        assertNotNull(hsmlib);
        prop.setProperty(Pkcs11NgCryptoToken.SHLIB_LABEL_KEY, hsmlib);
        prop.setProperty(Pkcs11NgCryptoToken.SLOT_LABEL_VALUE, PKCS11TestUtils.getPkcs11SlotValue("1"));
        prop.setProperty(Pkcs11NgCryptoToken.SLOT_LABEL_TYPE, PKCS11TestUtils.getPkcs11SlotType(Pkcs11SlotLabelType.SLOT_NUMBER.getKey()).getKey());
        if (file != null) {
            prop.setProperty(Pkcs11NgCryptoToken.ATTRIB_LABEL_KEY, file);
        }
        prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, "False");
        CryptoToken token = CryptoTokenFactory.createCryptoToken(CryptoTokenFactory.JACKNJI_NAME, prop, null, 111, "P11Ng CryptoToken");
        return token;
    }

    @Override
    protected String getProvider() {
        return JackNJI11Provider.NAME;
    }
    
    @Override
    protected void doCryptoTokenDSA(CryptoToken cryptoToken) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmParameterException  {
        // We have not activated the token so status should be offline
        assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
        assertEquals(getProvider(), cryptoToken.getSignProviderName());

        cryptoToken.activate(tokenpin.toCharArray());
        // Should still be ACTIVE now, because we run activate
        assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());

        // Generate a DSA key and wait for exception because DSA keys are not supported with this token type.
        cryptoToken.generateKeyPair("DSA1024", "dsatest00001");
    }
}
