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

import org.cesecore.keys.token.CryptoTokenTestBase;
import org.cesecore.keys.token.PKCS11TestUtils;

/**
 * Test class for Pkcs11Ng functions.
 * 
 * @version $Id$
 *
 */
public class Pkcs11NgCryptoTokenTest extends CryptoTokenTestBase {

    @Override
    protected String getProvider() {
        return PKCS11TestUtils.getHSMProvider();
    }
}
