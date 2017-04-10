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
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoTokenOfflineException;


/**
 * Interface for creating certificates
 *
 * Only one method from this bean is used.
 * 
 * @version $Id$
 */
public interface CertificateCreateSession {

    /**
     * Requests for a certificate to be created for the passed public key wrapped in a
     * certification request message (ex PKCS10).  The username and password used to authorize is
     * taken from the request message. Verification of the signature (proof-of-possesion) on the
     * request is performed, and an exception thrown if verification fails. The method queries the
     * user database for authorization of the user.
     *
     * @param admin         Information about the administrator or admin performing the event.
     * @param endEntityInformation Supplied user data, containing the issuing CAid, subject DN etc. Must contain the following information
     * 						type, username, certificateProfileId. Optionally it contains:
     * 						subjectDN, required if certificateProfile does not allow subject DN override
     * 						caid, if not possible to get it from issuerDN of the request
     * 						extendedInformation
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * @param responseClass The implementation class that will be used as the response message.
     * @param certGenParams Parameters for certificate generation (e.g for the CT extension), or null.
     * @return The newly created response or null.
     * 
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
	 * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either missing unique index in database, 
	 *     or certificate profile does not allow it
     * @throws IllegalKeyException (no rollback) if the passed in PublicKey does not fulfill requirements in CertificateProfile
     * @throws CertificateCreateException (rollback) if another error occurs
     * @throws CADoesntExistsException (no rollback) if CA to issue certificate does not exist
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException if certificate was meant to be issued revoked, but could not. Causes rollback. 
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws SignRequestSignatureException (no rollback) if POPO verification on the request fails 
     * @throws CryptoTokenOfflineException (no rollback) if token in the CA was unavailable. 
     * @throws CertificateExtensionException if any if the extensions were invalid
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CAOfflineException if the CA was offline
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * 
     */
    CertificateResponseMessage createCertificate(AuthenticationToken admin, EndEntityInformation endEntityInformation, RequestMessage req,
            Class<? extends ResponseMessage> responseClass, CertificateGenerationParams certGenParams) throws AuthorizationDeniedException, CustomCertificateSerialNumberException,
            IllegalKeyException, CADoesntExistsException, CertificateCreateException, CryptoTokenOfflineException, SignRequestSignatureException,
            IllegalNameException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException;

}
