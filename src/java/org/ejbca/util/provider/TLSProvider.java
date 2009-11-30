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
package org.ejbca.util.provider;

import java.security.Provider;

/**
 * Provider with to be used for TLS session.
 *
 * @author Lars Silven PrimeKey
 * @version  $Id$
 *
 */
public class TLSProvider extends Provider {
    private static final long serialVersionUID = 1L;
    private static String info = "EJBCA TLS Provider";
    public TLSProvider() {
        super("TLSProvider", 0.0, info);
        put("TrustManagerFactory.AcceptAll", "org.ejbca.util.provider.TrustManagerFactoryImpl$AcceptAll");
    }
}
