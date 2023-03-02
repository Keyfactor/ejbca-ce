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
package org.cesecore.junit.util;

import org.cesecore.SystemTestsConfiguration;

import com.keyfactor.util.keys.token.pkcs11.PKCS11CryptoToken;

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
        return PKCS11CryptoToken.class.getName();
    }

}
