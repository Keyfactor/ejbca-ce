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
package org.cesecore.certificates.certificate;

import java.math.BigInteger;

import javax.ejb.Remote;

/**
 * Interface for NoConflictCertificateStoreSession.
 * 
 * These methods call CertificateStoreSession for certificates that are plain CertificateData entities.
 * See {@link CertificateStoreSession} for method descriptions.
 * 
 * <p>For NoConflictCertificateData the methods perform additional logic to check that it gets the most recent
 * entry if there's more than one (taking permanent revocations into account), and for updates it
 * appends new entries instead of updating existing ones. 
 * 
 * @version $Id$
 */
@Remote
public interface NoConflictCertificateStoreSession  {

    /** @see CertificateStoreSession#getStatus */
    CertificateStatus getStatus(String issuerDN, BigInteger serno);
    
    /** @see CertificateStoreSession#getCertificateDataByIssuerAndSerno */
    CertificateDataWrapper getCertificateDataByIssuerAndSerno(String issuerdn, BigInteger certserno);
    
}
