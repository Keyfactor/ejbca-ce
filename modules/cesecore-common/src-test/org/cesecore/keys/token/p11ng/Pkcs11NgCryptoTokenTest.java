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

import java.security.Security;
import java.util.Properties;

import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenTestBase;
import org.cesecore.keys.token.PKCS11TestUtils;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken;
import org.cesecore.keys.token.p11ng.provider.JackNJI11Provider;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

/**
 * Test class for Pkcs11Ng functions.
 * 
 * @version $Id$
 *
 */
public class Pkcs11NgCryptoTokenTest extends CryptoTokenTestBase {

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
    }
    
    @Test
    public void testCryptoTokenRSA() throws Exception {
        CryptoToken catoken = createPkcs11NgToken();
        doCryptoTokenRSA(catoken);
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

}
