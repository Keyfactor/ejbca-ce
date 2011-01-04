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
package org.ejbca.core.protocol.certificatestore;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;

import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.model.log.Admin;

/**
 * Interface to the DB
 * 
 * @author primelars
 * @version $Id$
 *
 */
public interface ICertStore {
    /**
     * Get revocation status of a certificate
     * @param issuerDN
     * @param serialNumber
     * @return the status
     */
    CertificateStatus getStatus(String issuerDN, BigInteger serialNumber);
    /**
     * Search for certificate.
     * @param adm
     * @param issuerDN
     * @param serno
     * @return the certificate
     */
    Certificate findCertificateByIssuerAndSerno(Admin adm, String issuerDN, BigInteger serno);
    /**
     * 
     * @param adm
     * @param type
     * @param issuerDN
     * @return Collection of Certificate never null
     */
    Collection findCertificatesByType(Admin adm, int type, String issuerDN);
}
