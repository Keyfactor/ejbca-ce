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
package org.ejbca.core.ejb.ca.sign;

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;

import javax.ejb.ObjectNotFoundException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;

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
    Collection<Certificate> getCertificateChain(AuthenticationToken admin, int caid) throws AuthorizationDeniedException;

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
    byte[] createPKCS7(AuthenticationToken admin, Certificate cert, boolean includeChain) throws CADoesntExistsException,
            SignRequestSignatureException, AuthorizationDeniedException;

    /**
     * Creates a signed PKCS7 message containing the whole certificate chain of the specified CA.
     *
     * @param admin Information about the administrator or admin performing the event.
     * @param caId  CA for which we want a PKCS7 certificate chain.
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException if the CA does not exist or is expired, or has an invalid cert
     * @throws AuthorizationDeniedException 
     */
    byte[] createPKCS7(AuthenticationToken admin, int caId, boolean includeChain) throws CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Creates a roll over PKCS7 for the next CA certificate, signed by the current CA key. Used by ScepServlet.
     * @return A DER-encoded PKCS7 message, or null if there's no next CA certificate.
     */
    public byte[] createPKCS7Rollover(AuthenticationToken admin, int caId) throws CADoesntExistsException, AuthorizationDeniedException;
    
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
     * 
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
     * @throws CADoesntExistsException if the CA defined by caId doesn't exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     *             
     */
    Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKeyWrapper pk, int keyusage, Date notBefore,
            Date notAfter) throws ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException, AuthStatusException,
            AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException,
            CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException;
        
    /**
     * Requests for a certificate to be created for the passed public key with default key usage
     * The method queries the user database for authorization of the user.
     *
     * @param admin    Information about the administrator or admin performing the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk       the public key to be put in the created certificate.
     * @return The newly created certificate or null.
     * 
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
     * @throws CADoesntExistsException if the CA defined by caId doesn't exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     */
    Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKeyWrapper pk) throws ObjectNotFoundException,
            CADoesntExistsException, AuthorizationDeniedException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException, AuthStatusException, AuthLoginException;

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
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws SignRequestSignatureException if the provided client certificate was not signed 
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws CADoesntExistsException if the CA defined by caId doesn't exist.
     * 
     */
    Certificate createCertificate(AuthenticationToken admin, String username, String password, Certificate incert) throws ObjectNotFoundException,
            AuthorizationDeniedException, SignRequestSignatureException, CADoesntExistsException, AuthStatusException, AuthLoginException,
            IllegalKeyException, CertificateCreateException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CustomCertificateSerialNumberException;

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
     *                      in integer using constants from CertificateDataBean. ex. int keyusage =
     *                      CertificateDataBean.digitalSignature | CertificateDataBean.nonRepudiation; gives
     *                      digitalSignature and nonRepudiation. ex. int keyusage = CertificateDataBean.keyCertSign
     *                      | CertificateDataBean.cRLSign; gives keyCertSign and cRLSign. Keyusage < 0 means that default
     *                      keyUsage should be used, or should be taken from extensions in the request.
     * @param responseClass The implementation class that will be used as the response message.
     * @param suppliedUserData Optional (can be null) supplied user data, if we are running without storing UserData this will be used. Should only 
     *  be supplied when we issue certificates in a single transaction.
     *  
     * @return The newly created response or null.
     * 
     * @throws CertificateExtensionException if there was an error with the extensions specified in the request message
     * @throws NoSuchEndEntityException       if the user does not exist.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     * @throws CryptoTokenOfflineException 
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws IllegalKeyException           if the public key is of wrong type.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by the CA.
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined in the request was invalid 
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws AuthorizationDeniedException if the authentication token wasn't authorized to the CA defined in the request
     *
     */
    ResponseMessage createCertificate(AuthenticationToken admin, RequestMessage req, Class<? extends CertificateResponseMessage> responseClass,
            EndEntityInformation suppliedUserData) throws AuthorizationDeniedException, CertificateExtensionException, NoSuchEndEntityException,
            CustomCertificateSerialNumberException, CryptoTokenOfflineException, IllegalKeyException, CADoesntExistsException, SignRequestException,
            SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException,
            CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException;

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
     * 
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthorizationDeniedException (rollback) if admin is not authorized to issue this certificate
     * @throws CADoesntExistsException if the CA defined by caId doesn't exist.
     * @throws AuthStatusException     If the users status is incorrect.
     * @throws AuthLoginException      If the password is incorrect.
     * @throws InvalidAlgorithmException if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA was offline
     * @throws IllegalValidityException if the validity defined by notBefore and notAfter was invalid
     * @throws CryptoTokenOfflineException if the crypto token for the CA wasn't found
     * @throws CertificateSerialNumberException if certificate with same subject DN or key already exists for a user, if these limitations are enabled in CA.
     * @throws CertificateRevokeException (rollback) if certificate was meant to be issued revoked, but could not.
     * @throws IllegalNameException if the certificate request contained an illegal name 
     * @throws CertificateCreateException (rollback) if certificate couldn't be created.
     * @throws IllegalKeyException if the public key didn't conform to the constrains of the CA's certificate profile.
     * @throws CustomCertificateSerialNumberException (no rollback) if custom serial number is registered for user, but it is not allowed to be used (either
     *             missing unique index in database, or certificate profile does not allow it
     * 
     */
     Certificate createCertificate(AuthenticationToken admin, String username, String password, PublicKeyWrapper pk, int keyusage, Date notBefore,
            Date notAfter, int certificateprofileid, int caid) throws ObjectNotFoundException, CADoesntExistsException, AuthorizationDeniedException,
            AuthStatusException, AuthLoginException, IllegalKeyException, CertificateCreateException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, CryptoTokenOfflineException, IllegalValidityException, CAOfflineException,
            InvalidAlgorithmException, CustomCertificateSerialNumberException;

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
     * @return A decrypted and verified ResponseMessage message
     * 
     * @throws CryptoTokenOfflineException if the cryptotoken use by the CA defined in the request is unavailable
     * @throws AuthStatusException           If the users status is incorrect.
     * @throws AuthLoginException            If the password is incorrect.
     * @throws CADoesntExistsException       if the targeted CA does not exist
     * @throws SignRequestException          if the provided request is invalid.
     * @throws SignRequestSignatureException if the the request couldn't be verified.
     * @throws AuthorizationDeniedException if the authentication token wasn't authorized to the CA defined in the request
     * 
     */
    ResponseMessage createRequestFailedResponse(AuthenticationToken admin, RequestMessage req, Class<? extends ResponseMessage> responseClass,
            FailInfo failInfo, String failText) throws CADoesntExistsException, SignRequestSignatureException, CryptoTokenOfflineException, AuthorizationDeniedException;

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
    RequestMessage decryptAndVerifyRequest(AuthenticationToken admin, RequestMessage req) throws ObjectNotFoundException, AuthStatusException,
            AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException,
            CryptoTokenOfflineException, AuthorizationDeniedException;

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
    ResponseMessage getCRL(AuthenticationToken admin, RequestMessage req, Class<? extends ResponseMessage> responseClass)
            throws AuthStatusException, AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException,
            SignRequestSignatureException, UnsupportedEncodingException, CryptoTokenOfflineException, AuthorizationDeniedException;

    /**
     * Returns an object with configuration parameters for extensions (currently only for the CT extension).
     * This information is needed by CESeCore methods that create certificates, since it must be fetched
     * from the EJBCA configuration. Currently, this is needed in
     * {@link org.cesecore.certificates.certificate.CertificateCreateSession CertificateCreateSession} and {@link org.cesecore.certificates.ca.X509CA X509CA}.
     * 
     * The return value should only be passed directly into one of the CeSECore methods that use it.
     * There's no point in accessing it from EJBCA code.
     */
    CertificateGenerationParams fetchCertGenParams();
}
