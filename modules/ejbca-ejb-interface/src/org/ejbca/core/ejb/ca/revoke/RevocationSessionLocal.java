/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ca.revoke;

import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;

/**
 * @version $Id$
 */
@Local
public interface RevocationSessionLocal extends RevocationSession {

    /**
     * Revokes a certificate, in the database and in publishers. Also handles re-activation of suspended certificates.
     *
     * Re-activating (unrevoking) a certificate have two limitations.
     * 1. A password (for for example AD) will not be restored if deleted, only the certificate and certificate status and associated info will be restored
     * 2. ExtendedInformation, if used by a publisher will not be used when re-activating a certificate 
     * 
     * The method leaves up to the caller to find the correct publishers and userDataDN.
     *
     * @param admin      Administrator performing the operation
     * @param cdw        The certificate data
     * @param publishers and array of publisher ids (Integer) of publishers to revoke the certificate in.
     * @param revocationDate from when the certificates has been revoked
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate use object from user data instead.
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     */
    void revokeCertificate(AuthenticationToken admin, CertificateDataWrapper cdw, Collection<Integer> publishers, Date revocationDate, int reason,
            String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException;

    /**
     * Revokes a list of certificates, in the database and in publishers. Also handles re-activation of suspended certificates.
     *
     * @see RevocationSessionLocal#revokeCertificate(AuthenticationToken, CertificateDataWrapper, Collection, Date, int, String)
     *
     * @param admin      Administrator performing the operation
     * @param cdws       The list of certificate data wrappers.
     * @param publishers and array of publisher IDs (Integer) of publishers to revoke the certificate in.
     * @param reason the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.) 
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     */
    void revokeCertificates(AuthenticationToken admin, List<CertificateDataWrapper> cdw, Collection<Integer> publishers, int reason) throws CertificateRevokeException, AuthorizationDeniedException;
    
    /**
     * Revokes a certificate, in the database and in publishers, but does so in a new transaction. Also handles re-activation of suspended certificates.
     * Will do so in a new transaction. 
     * 
     * This method only needs to be used in cases where further actions rely on a certificate already being revoked, such as when producing a CRL as 
     * a result of CA revocation. 
     *
     * Re-activating (unrevoking) a certificate have two limitations.
     * 1. A password (for for example AD) will not be restored if deleted, only the certificate and certificate status and associated info will be restored
     * 2. ExtendedInformation, if used by a publisher will not be used when re-activating a certificate 
     * 
     * The method leaves up to the caller to find the correct publishers and userDataDN.
     *
     * @param admin      Administrator performing the operation
     * @param cdw        The certificate data
     * @param publishers and array of publisher ids (Integer) of publishers to revoke the certificate in.
     * @param revocationDate from when the certificates has been revoked
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate use object from user data instead.
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     */
    void revokeCertificateInNewTransaction(final AuthenticationToken admin, final CertificateDataWrapper cdw, final Collection<Integer> publishers,
            Date revocationDate, final int reason, final String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException;

    /**
     * Revokes incompletely issued certificates, that have been submitted to CT logs and/or published, but
     * where a rollback has happened after the submission/publication.
     * <p>
     * This method works in batches of 100 certificates, and returns 0 when there are no more certificates to revoke.
     *
     * @param admin  Administrator performing the operation
     * @param maxIssuanceTimeMillis  Time until a certificate issuance is considered to have failed.
     * @return  Number of revoked certificates, or 0 when there is nothing left to revoke.
     * @throws AuthorizationDeniedException (rollback)
     */
    int revokeIncompletelyIssuedCertsBatched(final AuthenticationToken admin, long maxIssuanceTimeMillis) throws AuthorizationDeniedException;

}
