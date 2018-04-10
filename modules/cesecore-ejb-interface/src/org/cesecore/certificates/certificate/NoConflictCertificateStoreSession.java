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
import java.util.Date;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Remote interface for NoConflictCertificateStoreSession.
 * 
 * @version $Id$
 */
@Remote
public interface NoConflictCertificateStoreSession  {

    CertificateDataWrapper getCertificateDataByIssuerAndSerno(String issuerdn, BigInteger certserno);
    
    boolean setRevokeStatus(AuthenticationToken admin, CertificateDataWrapper cdw, Date revokedDate, int reason) throws CertificateRevokeException, AuthorizationDeniedException;
    
}
