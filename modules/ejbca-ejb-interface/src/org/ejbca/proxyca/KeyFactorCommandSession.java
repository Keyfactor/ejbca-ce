/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.proxyca;

import java.security.cert.X509Certificate;
import java.util.Map;

public interface KeyFactorCommandSession {

    void invalidateToken(final String oAuthProvider);
    Map<Integer, X509Certificate> getCertificates(final String oAuthProvider) throws Exception;
    X509Certificate getCertificate(final String oAuthProvider, final int id) throws Exception;

}
