/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca.internal;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.cesecore.certificates.certificate.HashID;

/**
 * Allows for system testing of the CaCertificateCache
 */

public interface CaCertificateCacheTestSessionRemote {

    void loadCertificates(final Collection<Certificate> certs);
    X509Certificate findLatestBySubjectDN(final HashID id);
}
