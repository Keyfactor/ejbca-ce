package org.cesecore.keys.token.p11ng;

import org.cesecore.keys.token.CryptoTokenTestBase;
import org.cesecore.keys.token.PKCS11TestUtils;

public class Pkcs11NgCryptoTokenTest extends CryptoTokenTestBase {

    @Override
    protected String getProvider() {
        return PKCS11TestUtils.getHSMProvider();
    }
}
