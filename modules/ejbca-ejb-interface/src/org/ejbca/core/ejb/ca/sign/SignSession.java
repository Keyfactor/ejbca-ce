/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ca.sign;

import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;

import javax.ejb.ObjectNotFoundException;

import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.AuthLoginException;
import org.cesecore.certificates.ca.AuthStatusException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.EjbcaException;

/**
 * @version $Id$
 */
public interface SignSession {

    /**
     * Retrieves the certificate chain for the signer. The returned certificate chain MUST have the
     * RootCA certificate in the last position.
     *
     * @param admin Information about the administrator or admin performing the event.
     * @param caid  is the issuerdn.hashCode()
     * @return Collection of Certificate, the certificate chain, never null.
     * @throws AuthorizationDeniedException 
     */
    public java.util.Collection<Certificate> getCertificateChain(AuthenticationToken admin, int caid) throws AuthorizationDeniedException;

    /**
     * Creates a signed PKCS7 message containing the whole certificate chain, including the
     * provided client certificate.
     *
     * @param admin Information about the administrator or admin performing the event.
     * @param cert  client certificate which we want encapsulated in a PKCS7 together with
     *              certificate chain.
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException       if the CA does not exist or is expired, or has an invalid cert
     * @throws SignRequestSignatureException if the certificate is not signed by the CA
     * @throws AuthorizationDeniedException 
     */
    public byte[] createPKCS7(AuthenticationToken admin, Certificate cert, boolean includeChain) throws CADoesntExistsException, SignRequestSignatureException, AuthorizationDeniedException;

    /**
     * Creates a signed PKCS7 message containing the whole certificate chain of the specified CA.
     *
     * @param admin Information about the administrator or admin performing the event.
     * @param caId  CA for which we want a PKCS7 certificate chain.
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException if the CA does not exist or is expired, or has an invalid cert
     * @throws AuthorizationDeniedException 
     */
    public byte[] createPKCS7(AuthenticationToken admin, int caId, boolean includeChain) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Requests for a certificate to be created for the passed public key with default key usage
     * The method queries the user database for authorization of the user.
     *
     * @param admin    Information about the administrator or admin performing the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk       the public key to be put in the created certificate.
     * @return The newly created certificate or null.
     * @throws EjbcaException          if EJBCA did not accept any of all input parameters
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     * @throws CesecoreException 
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     */
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKey pk) throws EjbcaException, ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException, CesecoreException;

    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage. The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin    Information about the administrator or admin performing the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk       the public key to be put in the created certificate.
     * @param keyusage integer with bit mask describing desired keys usage, overrides keyUsage from
     *                 CertificateProfiles if allowed. Bit mask is packed in in integer using constants
     *                 from CertificateData. -1 means use default keyUsage from CertificateProfile. ex. int
     *                 keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *                 digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *                 | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @param notAfter an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
     * @return The newly created certificate or null.
     * @throws EjbcaException          if EJBCA did not accept any of all input parameters
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     * @throws CesecoreException 
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws IllegalKeyException     if the public key is of wrong type.
     */
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter) throws EjbcaException, ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException, CesecoreException;

    /**
     * Requests for a certificate to be created for the passed public key wrapped in a self-signed
     * certificate. Verification of the signature (proof-of-possession) on the request is
     * performed, and an exception thrown if verification fails. The method queries the user
     * database for authorization of the user.
     *
     * @param admin    Information about the administrator or admin performing the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param incert   a certificate containing the public key to be put in the created certificate.
     *                 Other (requested) parameters in the passed certificate can be used, such as DN,
     *                 Validity, KeyUsage etc. Currently only KeyUsage is considered!
     * @return The newly created certificate or null.
     * @throws ObjectNotFoundException       if the user does not exist.
     * @throws CesecoreException                if EJBCA did not accept any of all input parameters
     * @throws EjbcaException 
     * @throws AuthorizationDeniedException 
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     */
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, Certificate incert) throws ObjectNotFoundException, CesecoreException, AuthorizationDeniedException, EjbcaException;

    /**
     * Requests for a certificate to be created for the passed public key wrapped in a
     * certification request message (ex PKCS10).  The username and password used to authorize is
     * taken from the request message. Verification of the signature (proof-of-possesion) on the
     * request is performed, and an exception thrown if verification fails. The method queries the
     * user database for authorization of the user.
     *
     * @param admin         Information about the administrator or admin performing the event.
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * @param keyUsage      integer with bit mask describing desired keys usage. Bit mask is packed in
     *                      in integer using contants from CertificateDataBean. ex. int keyusage =
     *                      CertificateDataBean.digitalSignature | CertificateDataBean.nonRepudiation; gives
     *                      digitalSignature and nonRepudiation. ex. int keyusage = CertificateDataBean.keyCertSign
     *                      | CertificateDataBean.cRLSign; gives keyCertSign and cRLSign. Keyusage < 0 means that default
     *                      keyUsage should be used, or should be taken from extensions in the request.
     * @param responseClass The implementation class that will be used as the response message.
     * @param suppliedUserData Optional (can be null) supplied user data, if we are running without storing UserData this will be used. Should only be supplied when we issue certificates in a single transaction.
     * @return The newly created response or null.
     * @throws ObjectNotFoundException       if the user does not exist.
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *                                       the CA.
     * @see org.cesecore.certificates.certificate.CertificateData
     * @see org.cesecore.certificates.certificate.request.RequestMessage
     * @see org.cesecore.certificates.certificate.request.ResponseMessage
     * @see org.cesecore.certificates.certificate.request.X509ResponseMessage
     */
    public ResponseMessage createCertificate(AuthenticationToken admin, RequestMessage req, Class<? extends ResponseMessage> responseClass, EndEntityInformation suppliedUserData) throws EjbcaException, CesecoreException, AuthorizationDeniedException;

	/**
	 * Requests for a certificate to be created for the passed public key with the passed key
	 * usage and using the given certificate profile. This method is primarily intended to be used when
	 * issuing hardtokens having multiple certificates per user.
	 * The method queries the user database for authorization of the user. CAs are only
	 * allowed to have certificateSign and CRLSign set.
	 *
	 * @param admin                Information about the administrator or admin performing the event.
	 * @param username             unique username within the instance.
	 * @param password             password for the user.
	 * @param pk                   the public key to be put in the created certificate.
	 * @param keyusage             integer with bit mask describing desired keys usage, overrides keyUsage from
	 *                             CertificateProfiles if allowed. Bit mask is packed in in integer using constants
	 *                             from org.bouncycastle.jce.X509KeyUsage. -1 means use default keyUsage from CertificateProfile. ex. int
	 *                             keyusage = X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation; gives
	 *                             digitalSignature and nonRepudiation. ex. int keyusage = X509KeyUsage.keyCertSign
	 *                             | X509KeyUsage.cRLSign; gives keyCertSign and cRLSign
	 * @param notBefore an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
	 * @param notAfter an optional validity to set in the created certificate, if the profile allows validity override, null if the profiles default validity should be used.
	 * @param certificateprofileid used to override the one set in userdata.
	 *                             Should be set to CertificateProfileConstants.CERTPROFILE_NO_PROFILE if the usedata certificateprofileid should be used
	 * @param caid                 used to override the one set in userdata.
	 *                             Should be set to SecConst.CAID_USEUSERDEFINED if the regular certificateprofileid should be used
	 * 
	 * 
	 * @return The newly created certificate or null.
	 * @throws EjbcaException          if EJBCA did not accept any of all input parameters
	 * @throws ObjectNotFoundException if the user does not exist.
	 * @throws AuthorizationDeniedException 
	 * @throws CADoesntExistsException 
	 * @throws EjbcaException 
	 * @throws CesecoreException 
	 * @throws AuthStatusException     If the users status is incorrect.
	 * @throws AuthLoginException      If the password is incorrect.
	 * @throws IllegalKeyException     if the public key is of wrong type.
	 * 
     * @see org.bouncycastle.jce.X509KeyUsage
	 */
    public Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter, int certificateprofileid, int caid) 
    	throws ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException, EjbcaException, CesecoreException;

	/**
     * Method that generates a request failed response message. The request
     * should already have been decrypted and verified.
     *
     * @param admin         Information about the administrator or admin performing the event.
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * @param responseClass The implementation class that will be used as the response message.
     * @param failInfo the failure info in the failure response, for example FailInfo.BAD_REQUEST
     * @param failText free text failure message
     * 
     * @return A decrypted and verified IReqeust message
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the the request couldn't be verified.
     * @throws IllegalKeyException 
	 * @throws AuthorizationDeniedException 
     * @see org.cesecore.certificates.certificate.request.RequestMessage
     * @see org.cesecore.certificates.certificate.request.ResponseMessage
     * @see org.cesecore.certificates.certificate.request.X509ResponseMessage
     */
    public ResponseMessage createRequestFailedResponse(AuthenticationToken admin, RequestMessage req, Class<? extends ResponseMessage> responseClass, FailInfo failInfo, String failText) throws AuthLoginException,
            AuthStatusException, IllegalKeyException, CADoesntExistsException, SignRequestSignatureException, SignRequestException, CryptoTokenOfflineException, AuthorizationDeniedException;

    /**
     * Method that just decrypts and verifies a request and should be used in those cases
     * a when encrypted information needs to be extracted and presented to an RA for approval.
     *
     * @param admin         Information about the administrator or admin performing the event.
     * @param req           a Certification Request message, containing the public key to be put in the
     *                      created certificate. Currently no additional parameters in requests are considered!
     * 
     * @return A decrypted and verified IReqeust message
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the the request couldn't be verified.
     * @throws CryptoTokenOfflineException 
     * @throws AuthorizationDeniedException 
     * @see org.cesecore.certificates.certificate.request.RequestMessage
     * @see org.cesecore.certificates.certificate.request.ResponseMessage
     * @see org.cesecore.certificates.certificate.request.X509ResponseMessage
     */
    public RequestMessage decryptAndVerifyRequest(AuthenticationToken admin, RequestMessage req) throws ObjectNotFoundException, AuthStatusException,
    		AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, CryptoTokenOfflineException, AuthorizationDeniedException;

    /**
     * 
     * @param admin         Information about the administrator or admin performing the event.
     * @param req           a CRL Request message
     * @param responseClass the implementation class of the desired response
     * @return The newly created certificate or null.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *                                       the CA.
     * @throws CryptoTokenOfflineException 
     * @throws AuthorizationDeniedException 
     */
    public ResponseMessage getCRL(AuthenticationToken admin, RequestMessage req, Class<? extends ResponseMessage> responseClass) throws AuthStatusException, AuthLoginException,
            IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, UnsupportedEncodingException, CryptoTokenOfflineException, AuthorizationDeniedException;
}
