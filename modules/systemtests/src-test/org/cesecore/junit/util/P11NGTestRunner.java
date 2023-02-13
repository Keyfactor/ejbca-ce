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

import java.security.Security;

import org.cesecore.SystemTestsConfiguration;
import org.cesecore.keys.token.p11ng.provider.JackNJI11Provider;

/**
 *
 */
public class P11NGTestRunner extends HardtokenTestRunnerBase {

    private static final String P11NG_TOKEN_CLASSNAME = "org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken";
    
    public P11NGTestRunner() {
        Security.addProvider(new JackNJI11Provider());
    }
    

    @Override
    public String getNamingSuffix() {
        return "p11ng";
    }

    @Override
    public boolean canRun() {
        
        boolean p11ngPresent;
        try {
            Class.forName(P11NG_TOKEN_CLASSNAME, false, this.getClass().getClassLoader());
            p11ngPresent = true;
        } catch (ClassNotFoundException e) {
            p11ngPresent = false;
        }
        
        // true if there is a PKCS#11 library configured and the P11NG crypto token exists on the classpath
        return SystemTestsConfiguration.getPkcs11Library() != null && p11ngPresent;
    }

    @Override
    public String getSimpleName() {
        return "P11NGTestRunner";
    }
    
    @Override
    public String toString() {
        return getSimpleName();
    }


    @Override
    protected String getTokenImplementation() {
        return P11NG_TOKEN_CLASSNAME;
    }

}
