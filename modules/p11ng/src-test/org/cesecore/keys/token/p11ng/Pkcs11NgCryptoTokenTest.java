/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng;

import java.security.InvalidAlgorithmParameterException;
import java.security.Security;
import java.util.Properties;

import org.cesecore.keys.token.PKCS11CryptoToken;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import com.keyfactor.commons.p11ng.provider.JackNJI11Provider;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

/**
 * Test class for Pkcs11Ng functions, generating testing and deleting keys on a Crypto Token using P11NG.
 * 
 */
public class Pkcs11NgCryptoTokenTest extends CryptoTokenTestBase {

    private static final String JACKNJI_NAME = "org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken";

    
    CryptoToken token = null;
    
    @BeforeClass
    public static void beforeClass() {
        assumeTrue(getHSMLibrary() != null);
        assumeTrue(getHSMProvider() != null);
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @After
    public void tearDown() {
        // Make sure we remove the provider after one test, so it is not still there affecting the next test
        Security.removeProvider(getProvider());
    }
    
    @Test
    public void testCryptoTokenRSA() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doCryptoTokenRSA(token);
    }
    
    @Test
    public void testCryptoTokenECC() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doCryptoTokenECC(token, "secp256r1", 256, "secp384r1", 384);
    }

    /** Needs a rather new version of SoftHSM2 to pass this test, one that includes support for EdDSA */
    @Ignore
    public void testCryptoTokenEd25519() throws Exception {
        // HSMs only support Ed25519 so far (October 2020), not Ed448
        token = createPkcs11NgToken();
        token.deactivate();
        doCryptoTokenECC(token, "Ed25519", 255, "Ed25519", 255);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testCryptoTokenDSA() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doCryptoTokenDSA(token);
    }
    
    @Test
    public void testActivateDeactivate() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doActivateDeactivate(token);
    }
    
    @Test
    public void testAutoActivate() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doAutoActivate(token);
    }
    
    @Test
    public void testStoreAndLoad() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doStoreAndLoad(token);
    }
    
    private static CryptoToken createPkcs11NgToken() throws NoSuchSlotException {
        return createPkcs11NgTokenWithAttributesFile(null, null, true);
    }
    
    private static CryptoToken createPkcs11NgTokenWithAttributesFile(String file, String tokenName, boolean extractable) throws NoSuchSlotException {
        Properties prop = new Properties();
        String hsmlib = getHSMLibrary();
        assertNotNull(hsmlib);
        prop.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, hsmlib);
        prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE, getPkcs11SlotValue());
        prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE, getPkcs11SlotType().getKey());
        if (file != null) {
            prop.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, file);
        }
        prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, "False");
        CryptoToken token = createCryptoToken(JACKNJI_NAME, prop, null, 111, "P11Ng CryptoToken");
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
