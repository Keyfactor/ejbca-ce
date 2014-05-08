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
package org.cesecore.certificates.certificatetransparency;

import java.security.cert.X509Certificate;

import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Callback for audit logging CT pre-certificate submission during certificate generation in X509CA.
 * 
 * @version $Id$
 */
public interface CTAuditLogCallback {
    
    /**
     * Called after a pre-certificate has been submitted to CT logs, or on failure to submit it.
     */
    void logPreCertSubmission(X509CA issuer, EndEntityInformation subject, X509Certificate precert, boolean success);
}
