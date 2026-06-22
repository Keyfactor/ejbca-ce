/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.junit.util;

import org.cesecore.SystemTestsConfiguration;
import org.cesecore.keys.token.CryptoTokenFactory;

/**
 * Test runner for PKCS#11 crypto tokens
 */
public class PKCS11TestRunner extends HardtokenTestRunnerBase {

    public PKCS11TestRunner() {

    }

    @Override
    public String getNamingSuffix() {
        return "pkcs11";
    }

    @Override
    public boolean canRun() {
        // true if there is a PKCS#11 library configured
        return SystemTestsConfiguration.getPkcs11Library() != null;
    }

    @Override
    public String getSimpleName() {
        return "PKCS11TestRunner";
    }
    
    @Override
    public String toString() {
        return getSimpleName();
    }

    @Override
    protected String getTokenImplementation() {    
        return CryptoTokenFactory.PKCS11_NAME;
    }

}
