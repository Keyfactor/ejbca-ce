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
package org.cesecore.certificates.ca.kfenroll;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;

/**
 * Used to access the proxy-ca module. See KeyfactorEnrollerImpl in it.
 * (Available in specific editions of EJBCA only)
 */
public interface KeyfactorEnroller {

    X509Certificate enrollCertificate(ProxyCaInfo keyFactorCa, PKCS10RequestMessage csr) throws CertificateCreateException;

    ProxyCaCertificateInfo searchCertificate(ProxyCaInfo keyFactorCa, X509Certificate clientCertificate) throws CertificateCreateException;

    boolean validateCertificate(ProxyCaInfo keyFactorCa, String externalCertificateId) throws CertificateCreateException;

    List<Certificate> getCaCertificateChain(ProxyCaInfo keyFactorCa);

}