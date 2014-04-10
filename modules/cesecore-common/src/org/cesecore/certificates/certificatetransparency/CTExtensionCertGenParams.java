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
import java.util.Map;

import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Contains parameters and callbacks which is needed by the CT extension
 * during certificate generation in X509CA. This can be used to access
 * session beans from this class, for instance the global configuration
 * or audit logging. 
 * 
 * @note Since instances of this interface may reference, you must ensure
 * that instances of this interface are only used temporarily, e.g. as
 * functions arguments, and never as e.g. instance variables of non-temporary
 * classes.
 * 
 * @version $Id$
 */
public interface CTExtensionCertGenParams {

    /**
     * Returns the CT logs from the system configuration.
     */
    Map<Integer, CTLogInfo> getConfiguredCTLogs();

    /**
     * Called after a pre-certificate has been submitted to CT logs, or on failure to submit it.
     */
    void logPreCertSubmission(X509CA issuer, EndEntityInformation subject, X509Certificate precert, boolean success);
}
