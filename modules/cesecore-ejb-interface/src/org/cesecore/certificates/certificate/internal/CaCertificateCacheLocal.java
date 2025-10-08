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
package org.cesecore.certificates.certificate.internal;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.cesecore.certificates.certificate.HashID;

import jakarta.ejb.Local;

@Local
public interface CaCertificateCacheLocal {
    
    X509Certificate findLatestBySubjectDN(final HashID id);
    
    X509Certificate[] findLatestByIssuerDN(final HashID id);
    
    X509Certificate[] getRootCertificates();
    
    X509Certificate findBySubjectKeyIdentifier(final HashID id);
    
    boolean isCacheExpired();
    
    void loadCertificates(final Collection<Certificate> certs);

}
