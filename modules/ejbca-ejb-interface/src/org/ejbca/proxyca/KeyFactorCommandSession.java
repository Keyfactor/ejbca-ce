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

    void invalidateToken();
    Map<Integer, X509Certificate> getCertificates() throws Exception;
    X509Certificate getCertificate(final int id) throws Exception;

}
