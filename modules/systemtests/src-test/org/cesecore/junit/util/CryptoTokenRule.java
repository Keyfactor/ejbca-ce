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

import org.cesecore.certificates.ca.X509CA;
import org.cesecore.util.CryptoProviderTools;
import org.junit.rules.ExternalResource;

/**
 * @version $Id$
 *
 */
public class CryptoTokenRule extends ExternalResource {

    private static CryptoTokenRunner callback = null;

    public X509CA createX509Ca() throws Exception {
        if (callback == null) {
            throw new IllegalStateException("Can't create CA without an injected callback.");
        }
        return callback.createX509Ca();
    }

    public Integer createCryptoToken() throws Exception {
        if (callback == null) {
            throw new IllegalStateException("Can't create Crypto Token without an injected callback.");
        }
        return callback.createCryptoToken();
    }

    public void cleanUp() {
        if (callback == null) {
            throw new IllegalStateException("Can't tear down without an injected callback.");
        }
        callback.teardownCryptoToken();
        callback.tearDownAllCas();

    }

    @Override
    protected void before() throws Throwable {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    public static void setCallback(final CryptoTokenRunner callback) {
        CryptoTokenRule.callback = callback;
    }
}
