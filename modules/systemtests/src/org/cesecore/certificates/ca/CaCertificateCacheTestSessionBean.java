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
package org.cesecore.certificates.ca;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.cesecore.certificates.ca.internal.CaCertificateCacheTestSessionRemote;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.certificate.internal.CaCertificateCacheLocal;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

@Stateless
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class CaCertificateCacheTestSessionBean implements CaCertificateCacheTestSessionRemote {
    
    @EJB
    private CaCertificateCacheLocal caCertificateCache;

    @Override
    public void loadCertificates(Collection<Certificate> certs) {
        caCertificateCache.loadCertificates(certs);
    }

    @Override
    public JcaX509CertificateHolder findLatestBySubjectDN(HashID id) throws CertificateEncodingException {
        X509Certificate certificate = caCertificateCache.findLatestBySubjectDN(id);
        if (certificate == null) {
            return null;
        } else {
            return new JcaX509CertificateHolder(caCertificateCache.findLatestBySubjectDN(id));
                            }
    }

}
