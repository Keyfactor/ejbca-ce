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

import java.security.PublicKey;
import java.util.Date;

import javax.ejb.Local;

import org.bouncycastle.asn1.x509.Extensions;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
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
 * Local interface for CertificateCreateSession.
 * 
 * @version $Id$
 */
@Local
public interface CertificateCreateSessionLocal extends CertificateCreateSession {

	/** Helper method to check if there is a unique issuerDN/serialNumber index in the database 
	 * 
	 * @return true if the index exists, false if not
	 */
	boolean isUniqueCertificateSerialNumberIndex();
	
	/** Creates the certificate. This is the same method as createCertificate(AuthenticationToken admin, EndEntityInformation userData, RequestMessage req, Class<? extends ResponseMessage> responseClass)
	 * but also taking a CA as argument. the reason for this is that if we already have fetched the CA, going through access control etc there is no need to do the same thing again.
	 * 
     * @param admin         Information about the administrator or admin performing the event.
     * @param userData Supplied user data, containing the issuing CAid, subject DN etc. Must contain the following information
     *                      type, username, certificateProfileId. Optionally it contains:
     *                      subjectDN, required if certificateProfile does not allow subject DN override
     *                      caid, if not possible to get it from issuerDN of the request
     *                      extendedInformation
     * @param ca            the CA that should issue the certificate
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * @param responseClass The implementation class that will be used as the response message.
     * @param certGenParams Parameters for certificate generation (e.g for the CT extension), or null.
     * @param updateTime the time when this operation takes place
     * 
     * @return The newly created response or null.
     * 
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
	 * @throws CryptoTokenOfflineException (no rollback) if token in the CA was unavailable. 
	 * @throws SignRequestSignatureException (no rollback) if POPO verification on the request fails 
	 * @throws IllegalKeyException (no rollback) if the passed in PublicKey does not fulfill requirements in CertificateProfile
	 * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
	 * @throws CertificateRevokeException if certificate was meant to be issued revoked, but could not. Causes rollback. 
	 * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either missing unique index in database, or certificate profile does not allow it
     * @throws CertificateCreateException (rollback) (rollback) if certificate couldn't be created.
     * @throws CertificateExtensionException if any if the extensions (contained in the request) were invalid
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CAOfflineException if the CA was offline
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     *
	 */
    CertificateResponseMessage createCertificate(AuthenticationToken admin, EndEntityInformation userData, CA ca, RequestMessage req,
            Class<? extends ResponseMessage> responseClass, CertificateGenerationParams certGenParams, long updateTime) throws CryptoTokenOfflineException, SignRequestSignatureException, IllegalKeyException,
            IllegalNameException, CustomCertificateSerialNumberException, CertificateCreateException, CertificateRevokeException,
            CertificateSerialNumberException, AuthorizationDeniedException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException;

    /**
     * Requests for a certificate to be created for the passed public key wrapped in a
     * certification request message (ex PKCS10).  The username and password used to authorize is
     * taken from the request message. Verification of the signature (proof-of-possesion) on the
     * request is performed, and an exception thrown if verification fails. The method queries the
     * user database for authorization of the user.
     *
     * @param admin         Information about the administrator or admin performing the event.
     * @param userData Supplied user data, containing the issuing CAid, subject DN etc. Must contain the following information
     *                      type, username, certificateProfileId. Optionally it contains:
     *                      subjectDN, required if certificateProfile does not allow subject DN override
     *                      caid, if not possible to get it from issuerDN of the request
     *                      extendedInformation
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * @param responseClass The implementation class that will be used as the response message.
     * @param certGenParams Parameters for certificate generation (e.g for the CT extension), or null.
     * @param updateTime the time when this operation takes place
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
    CertificateResponseMessage createCertificate(AuthenticationToken admin, EndEntityInformation userData, RequestMessage req,
            Class<? extends ResponseMessage> responseClass, CertificateGenerationParams certGenParams, final long updateTime) throws AuthorizationDeniedException, CustomCertificateSerialNumberException,
            IllegalKeyException, CADoesntExistsException, CertificateCreateException, CryptoTokenOfflineException, SignRequestSignatureException,
            IllegalNameException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException;

    /**
     * Creates the certificate.
     * Does check that admin is authorized to CA, even though it is passed as a parameter.
     * Does check that admin has CREATE_CERTIFICATE right.
     * Does check authorization on certificate profile, i.e. that the CA is among available CAs in the certificate profile.
     * 
     * 
     * @param admin administrator performing this task
     * @param data auth data for user to get the certificate
     * @param ca the CA that will sign the certificate
     * @param RequestMessage the requestMessage if the certificate profile allows subject DN override the request DN from this request will be used instead of the value from subject.getDN
     * @param pk the users public key to be put in the certificate
     * @param keyUsage integer with bit mask describing desired keys usage, may be ignored by the CA. Bit mask is packed in in integer using constants
     *            from CertificateConstants. ex. int keyusage = CertificateConstants.digitalSignature | CertificateConstants.nonRepudiation; gives
     *            digitalSignature and nonRepudiation. ex. int keyusage = CertificateConstants.keyCertSign | CertificateConstants.cRLSign; gives
     *            keyCertSign and cRLSign. Keyusage < 0 means that default keyUsage should be used, or should be taken from extensions in the request.
     * @param notBefore an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default
     *            validity should be used.
     * @param notAfter an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default
     *            validity should be used.
     * @param extensions an optional set of extensions to set in the created certificate, if the profile allows extension override, null if the
     *            profile default extensions should be used.
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by
     *            CVC CAs for sequence field. Can be set to null.
     * @param certGenParams Parameters for certificate generation (e.g for the CT extension), or null.
     * @param updateTime the time when this operation takes place
     * @return Certificate that has been generated and signed by the CA, contained in a CertificateDataWrapper
     * 
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws CertificateExtensionException if any if the extensions were invalid
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CAOfflineException if the CA was offline
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * 
     */
    CertificateDataWrapper createCertificate(AuthenticationToken admin, EndEntityInformation data, CA ca, RequestMessage request, PublicKey pk, int keyusage,
            Date notBefore, Date notAfter, Extensions extensions, String sequence, CertificateGenerationParams certGenParams, long updateTime)
            throws AuthorizationDeniedException, IllegalNameException, CustomCertificateSerialNumberException, CertificateCreateException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalKeyException,
            CertificateExtensionException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException;

}
