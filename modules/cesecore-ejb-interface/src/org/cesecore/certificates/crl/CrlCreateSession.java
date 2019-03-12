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
package org.cesecore.certificates.crl;

import java.util.Collection;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Interface for CrlCreateSession, a session bean for generating CRLs and deltaCRLs.
 * Authorization for generating CRLs are handled by the fact that you need to be authorized to the CA. 
 * Authorization checks are thus done in CaSessionBean when this session retrieves the CA for CRL generation.
 * 
 * @version $Id$
 */
public interface CrlCreateSession {

    /**
     * Requests for a CRL to be created with the passed (revoked) certificates. 
     * Generates the CRL and stores it in the database.
     *
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @param crlPartitionIndex CRL partition index, or CertificateConstants.NO_CRL_PARTITION if partitioning is not used.
     * @param certs collection of RevokedCertInfo object.
     * @param basecrlnumber the CRL number of the Base CRL to generate a deltaCRL, -1 to generate a full CRL
     * @param nextCrlNumber the CRL number.
     * @return The newly created CRL in DER encoded byte form or null, use CertTools.getCRLfromByteArray to convert to X509CRL.
     * @throws AuthorizationDeniedException 
     * @throws CryptoTokenOfflineException 
     */
    byte[] generateAndStoreCRL(AuthenticationToken admin, CA ca, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int basecrlnumber, int nextCrlNumber)
            throws CryptoTokenOfflineException, AuthorizationDeniedException;

}
