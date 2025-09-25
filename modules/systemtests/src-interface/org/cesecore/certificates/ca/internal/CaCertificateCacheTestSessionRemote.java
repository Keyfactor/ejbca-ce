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
import java.security.cert.CertificateEncodingException;
import java.util.Collection;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.cesecore.certificates.certificate.HashID;

import jakarta.ejb.Remote;

/**
 * Allows for system testing of the CaCertificateCache
 */
@Remote
public interface CaCertificateCacheTestSessionRemote {

    void loadCertificates(final Collection<Certificate> certs);
    
    JcaX509CertificateHolder findLatestBySubjectDN(final HashID id) throws CertificateEncodingException;
}
