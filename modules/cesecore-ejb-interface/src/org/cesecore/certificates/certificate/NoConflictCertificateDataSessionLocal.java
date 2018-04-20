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

import java.util.List;

import javax.ejb.Local;

/**
 * Local interface for NoConflictCertificateDataSession.
 * 
 * @version $Id$
 */
@Local
public interface NoConflictCertificateDataSessionLocal extends NoConflictCertificateDataSession {

    List<NoConflictCertificateData> findByFingerprint(String fingerprint);
    
    /** @return return the query results as a List. */
    List<NoConflictCertificateData> findBySerialNumber(String serialNumber);

    /** @return return the query results as a List. */
    List<NoConflictCertificateData> findByIssuerDNSerialNumber(String issuerDN, String serialNumber);
    
}
