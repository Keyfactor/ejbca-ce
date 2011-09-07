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

import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;


/**
 * Interface for creating certificates
 *
 * Based on EJBCA version: SignSession.java 11374 2011-02-19 08:12:26Z anatom
 * 
 * Only one method from this bean is used.
 * 
 * @version $Id: CertificateCreateSession.java 667 2011-04-04 07:57:33Z mikek $
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
     * @param userData Supplied user data, containing the issuing CAid, subject DN etc. Must contain the following information
     * 						type, username, certificateProfileId. Optionally it contains:
     * 						subjectDN, required if certificateProfile does not allow subject DN override
     * 						caid, if not possible to get it from issuerDN of the request
     * 						extendedInformation
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * @param responseClass The implementation class that will be used as the response message.
     * @return The newly created response or null.
     * 
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
	 * @throws CustomCertSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either missing unique index in database, or certificate profile does not allow it
     * @throws IllegalKeyException (no rollback) if the passed in PublicKey does not fulfill requirements in CertificateProfile
     * @throws CertificateCreateException (rollback) if another error occurs
     * @throws CADoesntExistsException (no rollback) if CA to issue certificate does not exist
     * @throws CesecoreException (no rollback) if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * 
     * @see org.cesecore.certificates.certificate.request.RequestMessage
     * @see org.cesecore.certificates.certificate.request.ResponseMessage
     * @see org.cesecore.certificates.certificate.request.X509ResponseMessage
     */
    CertificateResponseMessage createCertificate(AuthenticationToken admin, EndEntityInformation userData, RequestMessage req, Class responseClass) throws AuthorizationDeniedException, CustomCertSerialNumberException, IllegalKeyException, CADoesntExistsException, CertificateCreateException, CesecoreException;
	
}
