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

public interface SignSession {

    public boolean isUniqueCertificateSerialNumberIndex();

    /**
     * Retrieves the certificate chain for the signer. The returned certificate
     * chain MUST have the RootCA certificate in the last position.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param caid
     *            is the issuerdn.hashCode()
     * @return Collection of Certificate, the certificate chain, never null.
     */
    public java.util.Collection getCertificateChain(org.ejbca.core.model.log.Admin admin, int caid);

    /**
     * Creates a signed PKCS7 message containing the whole certificate chain,
     * including the provided client certificate.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param cert
     *            client certificate which we want encapsulated in a PKCS7
     *            together with certificate chain.
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException
     *             if the CA does not exist or is expired, or has an invalid
     *             cert
     * @throws SignRequestSignatureException
     *             if the certificate is not signed by the CA
     */
    public byte[] createPKCS7(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate cert, boolean includeChain)
            throws org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.model.ca.SignRequestSignatureException;

    /**
     * Creates a signed PKCS7 message containing the whole certificate chain of
     * the specified CA.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param caId
     *            CA for which we want a PKCS7 certificate chain.
     * @return The DER-encoded PKCS7 message.
     * @throws CADoesntExistsException
     *             if the CA does not exist or is expired, or has an invalid
     *             cert
     */
    public byte[] createPKCS7(org.ejbca.core.model.log.Admin admin, int caId, boolean includeChain)
            throws org.ejbca.core.model.ca.caadmin.CADoesntExistsException;

    /**
     * Requests for a certificate to be created for the passed public key with
     * default key usage The method queries the user database for authorization
     * of the user.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param username
     *            unique username within the instance.
     * @param password
     *            password for the user.
     * @param pk
     *            the public key to be put in the created certificate.
     * @return The newly created certificate or null.
     * @throws EjbcaException
     *             if EJBCA did not accept any of all input parameters
     * @throws ObjectNotFoundException
     *             if the user does not exist.
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     */
    public java.security.cert.Certificate createCertificate(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password,
            java.security.PublicKey pk) throws org.ejbca.core.EjbcaException, javax.ejb.ObjectNotFoundException;

    /**
     * Requests for a certificate to be created for the passed public key with
     * the passed key usage. The method queries the user database for
     * authorization of the user. CAs are only allowed to have certificateSign
     * and CRLSign set.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param username
     *            unique username within the instance.
     * @param password
     *            password for the user.
     * @param pk
     *            the public key to be put in the created certificate.
     * @param keyusage
     *            integer with mask describing desired key usage in format
     *            specified by X509Certificate.getKeyUsage(). id-ce-keyUsage
     *            OBJECT IDENTIFIER ::= { id-ce 15 } KeyUsage ::= BIT STRING {
     *            digitalSignature (0), nonRepudiation (1), keyEncipherment (2),
     *            dataEncipherment (3), keyAgreement (4), keyCertSign (5),
     *            cRLSign (6), encipherOnly (7), decipherOnly (8) }
     * @return The newly created certificate or null.
     * @throws EjbcaException
     *             if EJBCA did not accept any of all input parameters
     * @throws ObjectNotFoundException
     *             if the user does not exist.
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     */
    public java.security.cert.Certificate createCertificate(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password,
            java.security.PublicKey pk, boolean[] keyusage) throws org.ejbca.core.EjbcaException, javax.ejb.ObjectNotFoundException;

    /**
     * Requests for a certificate to be created for the passed public key with
     * the passed key usage. The method queries the user database for
     * authorization of the user. CAs are only allowed to have certificateSign
     * and CRLSign set.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param username
     *            unique username within the instance.
     * @param password
     *            password for the user.
     * @param pk
     *            the public key to be put in the created certificate.
     * @param keyusage
     *            integer with bit mask describing desired keys usage, overrides
     *            keyUsage from CertificateProfiles if allowed. Bit mask is
     *            packed in in integer using constants from CertificateData. -1
     *            means use default keyUsage from CertificateProfile. ex. int
     *            keyusage = CertificateData.digitalSignature |
     *            CertificateData.nonRepudiation; gives digitalSignature and
     *            nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *            | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @return The newly created certificate or null.
     * @throws EjbcaException
     *             if EJBCA did not accept any of all input parameters
     * @throws ObjectNotFoundException
     *             if the user does not exist.
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     */
    public java.security.cert.Certificate createCertificate(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password,
            java.security.PublicKey pk, int keyusage) throws javax.ejb.ObjectNotFoundException, org.ejbca.core.EjbcaException;

    /**
     * Requests for a certificate to be created for the passed public key with
     * the passed key usage. The method queries the user database for
     * authorization of the user. CAs are only allowed to have certificateSign
     * and CRLSign set.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param username
     *            unique username within the instance.
     * @param password
     *            password for the user.
     * @param pk
     *            the public key to be put in the created certificate.
     * @param keyusage
     *            integer with bit mask describing desired keys usage, overrides
     *            keyUsage from CertificateProfiles if allowed. Bit mask is
     *            packed in in integer using constants from CertificateData. -1
     *            means use default keyUsage from CertificateProfile. ex. int
     *            keyusage = CertificateData.digitalSignature |
     *            CertificateData.nonRepudiation; gives digitalSignature and
     *            nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *            | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @param notAfter
     *            an optional validity to set in the created certificate, if the
     *            profile allows validity override, null if the profiles default
     *            validity should be used.
     * @return The newly created certificate or null.
     * @throws EjbcaException
     *             if EJBCA did not accept any of all input parameters
     * @throws ObjectNotFoundException
     *             if the user does not exist.
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     */
    public java.security.cert.Certificate createCertificate(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password,
            java.security.PublicKey pk, int keyusage, java.util.Date notBefore, java.util.Date notAfter) throws org.ejbca.core.EjbcaException,
            javax.ejb.ObjectNotFoundException;

    /**
     * Requests for a certificate of the specified type to be created for the
     * passed public key. The method queries the user database for authorization
     * of the user.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param username
     *            unique username within the instance.
     * @param password
     *            password for the user.
     * @param certType
     *            integer type of certificate taken from
     *            CertificateData.CERT_TYPE_XXX. the type
     *            CertificateData.CERT_TYPE_ENCRYPTION gives keyUsage
     *            keyEncipherment, dataEncipherment. the type
     *            CertificateData.CERT_TYPE_SIGNATURE gives keyUsage
     *            digitalSignature, non-repudiation. all other CERT_TYPES gives
     *            the default keyUsage digitalSignature, keyEncipherment
     * @param pk
     *            the public key to be put in the created certificate.
     * @return The newly created certificate or null.
     * @throws EjbcaException
     *             if EJBCA did not accept any of all input parameters
     * @throws ObjectNotFoundException
     *             if the user does not exist.
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     */
    public java.security.cert.Certificate createCertificate(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password,
            int certType, java.security.PublicKey pk) throws org.ejbca.core.EjbcaException, javax.ejb.ObjectNotFoundException;

    /**
     * Requests for a certificate to be created for the passed public key
     * wrapped in a self-signed certificate. Verification of the signature
     * (proof-of-possesion) on the request is performed, and an exception thrown
     * if verification fails. The method queries the user database for
     * authorization of the user.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param username
     *            unique username within the instance.
     * @param password
     *            password for the user.
     * @param incert
     *            a certificate containing the public key to be put in the
     *            created certificate. Other (requested) parameters in the
     *            passed certificate can be used, such as DN, Validity, KeyUsage
     *            etc. Currently only KeyUsage is considered!
     * @return The newly created certificate or null.
     * @throws EjbcaException
     *             if EJBCA did not accept any of all input parameters
     * @throws ObjectNotFoundException
     *             if the user does not exist.
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     * @throws SignRequestSignatureException
     *             if the provided client certificate was not signed by the CA.
     */
    public java.security.cert.Certificate createCertificate(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password,
            java.security.cert.Certificate incert) throws org.ejbca.core.EjbcaException, javax.ejb.ObjectNotFoundException;

    /**
     * Requests for a certificate to be created for the passed public key
     * wrapped in a certification request message (ex PKCS10). Verification of
     * the signature (proof-of-possesion) on the request is performed, and an
     * exception thrown if verification fails. The method queries the user
     * database for authorization of the user.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param req
     *            a Certification Request message, containing the public key to
     *            be put in the created certificate. Currently no additional
     *            parameters in requests are considered! Currently no additional
     *            parameters in the PKCS10 request is considered!
     * @param responseClass
     *            The implementation class that will be used as the response
     *            message.
     * @return The newly created response message or null.
     * @throws ObjectNotFoundException
     *             if the user does not exist.
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     * @throws SignRequestException
     *             if the provided request is invalid.
     * @throws SignRequestSignatureException
     *             if the provided client certificate was not signed by the CA.
     */
    public org.ejbca.core.protocol.IResponseMessage createCertificate(org.ejbca.core.model.log.Admin admin, org.ejbca.core.protocol.IRequestMessage req,
            java.lang.Class responseClass) throws org.ejbca.core.EjbcaException;

    /**
     * Requests for a certificate to be created for the passed public key with
     * the passed key usage and using the given certificate profile. This method
     * is primarily intended to be used when issueing hardtokens having multiple
     * certificates per user. The method queries the user database for
     * authorization of the user. CAs are only allowed to have certificateSign
     * and CRLSign set.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param username
     *            unique username within the instance.
     * @param password
     *            password for the user.
     * @param pk
     *            the public key to be put in the created certificate.
     * @param keyusage
     *            integer with bit mask describing desired keys usage, overrides
     *            keyUsage from CertificateProfiles if allowed. Bit mask is
     *            packed in in integer using constants from CertificateData. -1
     *            means use default keyUsage from CertificateProfile. ex. int
     *            keyusage = CertificateData.digitalSignature |
     *            CertificateData.nonRepudiation; gives digitalSignature and
     *            nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *            | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @param certificateprofileid
     *            used to override the one set in userdata. Should be set to
     *            SecConst.PROFILE_NO_PROFILE if the usedata
     *            certificateprofileid should be used
     * @param caid
     *            used to override the one set in userdata.� Should be set to
     *            SecConst.CAID_USEUSERDEFINED if the regular
     *            certificateprofileid should be used
     * @return The newly created certificate or null.
     * @throws EjbcaException
     *             if EJBCA did not accept any of all input parameters
     * @throws ObjectNotFoundException
     *             if the user does not exist.
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     */
    public java.security.cert.Certificate createCertificate(org.ejbca.core.model.log.Admin admin, java.lang.String username, java.lang.String password,
            java.security.PublicKey pk, int keyusage, int certificateprofileid, int caid) throws org.ejbca.core.EjbcaException,
            javax.ejb.ObjectNotFoundException;

    /**
     * Requests for a certificate to be created for the passed public key
     * wrapped in a certification request message (ex PKCS10). The username and
     * password used to authorize is taken from the request message.
     * Verification of the signature (proof-of-possesion) on the request is
     * performed, and an exception thrown if verification fails. The method
     * queries the user database for authorization of the user.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param req
     *            a Certification Request message, containing the public key to
     *            be put in the created certificate. Currently no additional
     *            parameters in requests are considered!
     * @param keyUsage
     *            integer with bit mask describing desired keys usage. Bit mask
     *            is packed in in integer using contants from
     *            CertificateDataBean. ex. int keyusage =
     *            CertificateDataBean.digitalSignature |
     *            CertificateDataBean.nonRepudiation; gives digitalSignature and
     *            nonRepudiation. ex. int keyusage =
     *            CertificateDataBean.keyCertSign | CertificateDataBean.cRLSign;
     *            gives keyCertSign and cRLSign. Keyusage < 0 means that default
     *            keyUsage should be used, or should be taken from extensions in
     *            the request.
     * @param responseClass
     *            The implementation class that will be used as the response
     *            message.
     * @return The newly created response or null.
     * @throws ObjectNotFoundException
     *             if the user does not exist.
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     * @throws CADoesntExistsException
     *             if the targeted CA does not exist
     * @throws SignRequestException
     *             if the provided request is invalid.
     * @throws SignRequestSignatureException
     *             if the provided client certificate was not signed by the CA.
     * @see org.ejbca.core.ejb.ca.store.CertificateDataBean
     * @see org.ejbca.core.protocol.IRequestMessage
     * @see org.ejbca.core.protocol.IResponseMessage
     * @see org.ejbca.core.protocol.X509ResponseMessage
     */
    public org.ejbca.core.protocol.IResponseMessage createCertificate(org.ejbca.core.model.log.Admin admin, org.ejbca.core.protocol.IRequestMessage req,
            int keyUsage, java.lang.Class responseClass) throws org.ejbca.core.EjbcaException;

    /**
     * Method that generates a request failed response message. The request
     * should already have been decrypted and verified.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param req
     *            a Certification Request message, containing the public key to
     *            be put in the created certificate. Currently no additional
     *            parameters in requests are considered!
     * @param responseClass
     *            The implementation class that will be used as the response
     *            message.
     * @return A decrypted and verified IReqeust message
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws CADoesntExistsException
     *             if the targeted CA does not exist
     * @throws SignRequestException
     *             if the provided request is invalid.
     * @throws SignRequestSignatureException
     *             if the the request couldn't be verified.
     * @throws IllegalKeyException
     * @see org.ejbca.core.protocol.IRequestMessage
     * @see org.ejbca.core.protocol.IResponseMessage
     * @see org.ejbca.core.protocol.X509ResponseMessage
     */
    public org.ejbca.core.protocol.IResponseMessage createRequestFailedResponse(org.ejbca.core.model.log.Admin admin,
            org.ejbca.core.protocol.IRequestMessage req, java.lang.Class responseClass) throws org.ejbca.core.model.ca.AuthLoginException,
            org.ejbca.core.model.ca.AuthStatusException, org.ejbca.core.model.ca.IllegalKeyException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException,
            org.ejbca.core.model.ca.SignRequestSignatureException, org.ejbca.core.model.ca.SignRequestException;

    /**
     * Method that just decrypts and verifies a request and should be used in
     * those cases a when encrypted information needs to be extracted and
     * presented to an RA for approval.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param req
     *            a Certification Request message, containing the public key to
     *            be put in the created certificate. Currently no additional
     *            parameters in requests are considered!
     * @return A decrypted and verified IReqeust message
     * @throws AuthStatusException
     *             If the users status is incorrect.
     * @throws AuthLoginException
     *             If the password is incorrect.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     * @throws CADoesntExistsException
     *             if the targeted CA does not exist
     * @throws SignRequestException
     *             if the provided request is invalid.
     * @throws SignRequestSignatureException
     *             if the the request couldn't be verified.
     * @see org.ejbca.core.protocol.IRequestMessage
     * @see org.ejbca.core.protocol.IResponseMessage
     * @see org.ejbca.core.protocol.X509ResponseMessage
     */
    public org.ejbca.core.protocol.IRequestMessage decryptAndVerifyRequest(org.ejbca.core.model.log.Admin admin, org.ejbca.core.protocol.IRequestMessage req)
            throws javax.ejb.ObjectNotFoundException, org.ejbca.core.model.ca.AuthStatusException, org.ejbca.core.model.ca.AuthLoginException,
            org.ejbca.core.model.ca.IllegalKeyException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.model.ca.SignRequestException,
            org.ejbca.core.model.ca.SignRequestSignatureException;

    /**
     * Implements ISignSession::getCRL
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param req
     *            a CRL Request message
     * @param responseClass
     *            the implementation class of the desired response
     * @return The newly created certificate or null.
     * @throws IllegalKeyException
     *             if the public key is of wrong type.
     * @throws CADoesntExistsException
     *             if the targeted CA does not exist
     * @throws SignRequestException
     *             if the provided request is invalid.
     * @throws SignRequestSignatureException
     *             if the provided client certificate was not signed by the CA.
     */
    public org.ejbca.core.protocol.IResponseMessage getCRL(org.ejbca.core.model.log.Admin admin, org.ejbca.core.protocol.IRequestMessage req,
            java.lang.Class responseClass) throws org.ejbca.core.model.ca.AuthStatusException, org.ejbca.core.model.ca.AuthLoginException,
            org.ejbca.core.model.ca.IllegalKeyException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException, org.ejbca.core.model.ca.SignRequestException,
            org.ejbca.core.model.ca.SignRequestSignatureException, java.io.UnsupportedEncodingException;

    /**
     * Sign an array of bytes with CA.
     * 
     * @param keyPupose
     *            one of SecConst.CAKEYPURPOSE_...
     */
    public byte[] signData(byte[] data, int caId, int keyPurpose) throws java.security.NoSuchAlgorithmException,
            org.ejbca.core.model.ca.catoken.CATokenOfflineException, org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException,
            java.security.InvalidKeyException, java.security.SignatureException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException;

    /**
     * Verify an array of bytes with a signature
     * 
     * @param keyPupose
     *            one of SecConst.CAKEYPURPOSE_...
     */
    public boolean verifySignedData(byte[] data, int caId, int keyPurpose, byte[] signature) throws org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException,
            org.ejbca.core.model.ca.catoken.CATokenOfflineException, java.security.NoSuchAlgorithmException, java.security.InvalidKeyException,
            java.security.SignatureException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException;

    /**
     * Method used to perform a extended CA Service, like OCSP CA Service.
     * 
     * @param admin
     *            Information about the administrator or admin preforming the
     *            event.
     * @param caid
     *            the ca that should perform the service
     * @param request
     *            a service request.
     * @return A corresponding response.
     * @throws IllegalExtendedCAServiceRequestException
     *             if the request was invalid.
     * @throws ExtendedCAServiceNotActiveException
     *             thrown when the service for the given CA isn't activated
     * @throws CADoesntExistsException
     *             The given caid doesn't exists.
     */
    public org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse extendedService(org.ejbca.core.model.log.Admin admin, int caid,
            org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest request)
            throws org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException,
            org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException,
            org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException, org.ejbca.core.model.ca.caadmin.CADoesntExistsException;

}
