/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Interface for basic CRUD operations related to CertificateData 
 * 
 */
public interface CertificateDataSession {
    
    /**
     * Returns the number of total or active certificates.
     *
     * @param adminToken an admin authentication token.
     * @param isActive if true then returns the number of active certificates only.
     * @return certificate quantity.
     */
    Long getCertificateCount(AuthenticationToken adminToken, Boolean isActive) throws AuthorizationDeniedException;
    
}
