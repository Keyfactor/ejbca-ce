/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.cesecore.certificates.ca.X509CA;
import org.cesecore.util.CryptoProviderTools;
import org.junit.rules.ExternalResource;

/**
 * @version $Id$
 *
 */
public class CryptoTokenRule extends ExternalResource {

    private static Method caCreationMethod = null;
    private static Method caTearDownMethod = null;
    private static Method cryptoTokenCreationMethod = null;
    private static Method cryptoTokenTearDownMethod = null;
    private static CryptoTokenRunner callback = null;

    public X509CA createX509Ca() {
        if (caCreationMethod == null) {
            throw new IllegalStateException("Can't create CA without an injected method.");
        }
        try {
            return (X509CA) caCreationMethod.invoke(callback);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(e);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(e);
        }
    }

    public Integer createCryptoToken() {
        if (cryptoTokenCreationMethod == null) {
            throw new IllegalStateException("Can't create CryptoToken without an injected method.");
        }
        try {
            return (int) cryptoTokenCreationMethod.invoke(callback);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(e);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(e);
        }
    }

    public static void cleanUp() {
        if (caTearDownMethod == null) {
            throw new IllegalStateException("Can't create CA without an injected method.");
        }
        try {
            caTearDownMethod.invoke(callback);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(e);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(e);
        }
        if (cryptoTokenTearDownMethod == null) {
            throw new IllegalStateException("Can't create CA without an injected method.");
        }
        try {
            cryptoTokenTearDownMethod.invoke(callback);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(e);
        } catch (InvocationTargetException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected void before() throws Throwable {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    public static void setCreationMethod(final CryptoTokenRunner callback, final Method caCreationMethod, final Method caTearDownMethod,
            final Method cryptoTokenCreationMethod, final Method cryptoTokenTearDownMethod) {
        CryptoTokenRule.callback = callback;
        CryptoTokenRule.caCreationMethod = caCreationMethod;
        CryptoTokenRule.caTearDownMethod = caTearDownMethod;
        CryptoTokenRule.cryptoTokenCreationMethod = cryptoTokenCreationMethod;
        CryptoTokenRule.cryptoTokenTearDownMethod = cryptoTokenTearDownMethod;
    }
}
