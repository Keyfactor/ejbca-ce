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
 
package se.anatom.ejbca.ca.sign;

import java.rmi.RemoteException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.Collection;
import java.util.Vector;

import javax.ejb.ObjectNotFoundException;

import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.exception.IllegalKeyException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;

/**
 * Creates certificates. Remote interface for EJB.
 *
 * @version $Id: ISignSessionRemote.java,v 1.29 2004-05-22 12:58:52 anatom Exp $
 */
public interface ISignSessionRemote extends javax.ejb.EJBObject {
	/**
	 * Retrieves the certificate chain for the signer. The returned certificate chain MUST have the
	 * RootCA certificate in the last position.
	 *
	 * @param admin Information about the administrator or admin preforming the event.
	 *
	 * @return The certificate chain, never null.
	 *
	 * @throws RemoteException if a communication or other error occurs.
	 */
    public Collection getCertificateChain(Admin admin, int caid) throws RemoteException;

	/**
	 * Creates a signed PKCS7 message containing the whole certificate chain, including the
	 * provided client certificate.
	 *
	 * @param admin Information about the administrator or admin preforming the event.
	 * @param cert client certificate which we want encapsulated in a PKCS7 together with
	 *        certificate chain.
	 *
	 * @return The DER-encoded PKCS7 message.
	 *
     * @throws CADoesntExistsException if the CA does not exist or is expired, or has an invalid cert
     * @throws SignRequestSignatureException if the certificate is not signed by the CA
	 * @throws RemoteException if a communication or other error occurs.
	 */
	public byte[] createPKCS7(Admin admin, Certificate cert) throws CADoesntExistsException, SignRequestSignatureException, RemoteException;

	/**
	 * Creates a signed PKCS7 message containing the whole certificate chain of the specified CA.
	 *
	 * @param admin Information about the administrator or admin preforming the event.
	 * @param caId CA for which we want a PKCS7 certificate chain.
	 *
	 * @return The DER-encoded PKCS7 message.
	 *
     * @throws CADoesntExistsException if the CA does not exist or is expired, or has an invalid cert
	 * @throws RemoteException if a communication or other error occurs.
	 */	
	public byte[] createPKCS7(Admin admin, int caId) throws CADoesntExistsException, RemoteException;
        
	/**
         * Requests for a certificate to be created for the passed public key with default key usage
         * The method queries the user database for authorization of the user.
         *
         * @param admin Information about the administrator or admin preforming the event.
         * @param username unique username within the instance.
         * @param password password for the user.
         * @param pk the public key to be put in the created certificate.
         *
         * @return The newly created certificate or null.
         *
         * @throws ObjectNotFoundException if the user does not exist.
         * @throws AuthStatusException If the users status is incorrect.
         * @throws AuthLoginException If the password is incorrect.
         * @throws IllegalKeyException if the public key is of wrong type.
         * @throws RemoteException if a communication or other error occurs.
         */		
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk)
        throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException;

    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage. The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk the public key to be put in the created certificate.
     * @param keyusage integer with mask describing desired key usage in format specified by
     *        X509Certificate.getKeyUsage(). id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
     *        KeyUsage ::= BIT STRING { digitalSignature        (0), nonRepudiation          (1),
     *        keyEncipherment         (2), dataEncipherment        (3), keyAgreement (4),
     *        keyCertSign             (5), cRLSign                 (6), encipherOnly (7),
     *        decipherOnly            (8) }
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws RemoteException if a communication or other error occurs.
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        PublicKey pk, boolean[] keyusage)
        throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException;

    /**
     * Requests for a certificate to be created for the passed public key with the passed key
     * usage. The method queries the user database for authorization of the user. CAs are only
     * allowed to have certificateSign and CRLSign set.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param pk the public key to be put in the created certificate.
     * @param keyusage integer with bit mask describing desired keys usage, overrides keyUsage from
     *        CertificateProfiles if allowed. Bit mask is packed in in integer using constants
     *        from CertificateData. -1 means use default keyUsage from CertificateProfile. ex. int
     *        keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *        digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *        | CertificateData.cRLSign; gives keyCertSign and cRLSign
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws RemoteException if a communication or other error occurs.
     *
     * @see se.anatom.ejbca.ca.store.CertificateData
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        PublicKey pk, int keyusage)
        throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException;

    /**
     * Requests for a certificate of the specified type to be created for the passed public key.
     * The method queries the user database for authorization of the user.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param certType integer type of certificate taken from CertificateData.CERT_TYPE_XXX. the
     *        type CertificateData.CERT_TYPE_ENCRYPTION gives keyUsage keyEncipherment,
     *        dataEncipherment. the type CertificateData.CERT_TYPE_SIGNATURE gives keyUsage
     *        digitalSignature, non-repudiation. all other CERT_TYPES gives the default keyUsage
     *        digitalSignature, keyEncipherment
     * @param pk the public key to be put in the created certificate.
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws RemoteException if a communication or other error occurs.
     *
     * @see se.anatom.ejbca.ca.store.CertificateData
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        int certType, PublicKey pk)
        throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException;

    /**
     * Requests for a certificate to be created for the passed public key wrapped in a self-signed
     * certificate. Verification of the signature (proof-of-possesion) on the request is
     * performed, and an exception thrown if verification fails. The method queries the user
     * database for authorization of the user.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param username unique username within the instance.
     * @param password password for the user.
     * @param incert a certificate containing the public key to be put in the created certificate.
     *        Other (requested) parameters in the passed certificate can be used, such as DN,
     *        Validity, KeyUsage etc. Currently only KeyUsage is considered!
     *
     * @return The newly created certificate or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *         the CA.
     * @throws RemoteException if a communication or other error occurs.
     */
    public Certificate createCertificate(Admin admin, String username, String password,
        Certificate incert)
        throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException, SignRequestSignatureException;

    /**
     * Requests for a certificate to be created for the passed public key wrapped in a
     * certification request message (ex PKCS10). Verification of the signature
     * (proof-of-possesion) on the request is performed, and an exception thrown if verification
     * fails. The method queries the user database for authorization of the user.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param req a Certification Request message, containing the public key to be put in the
     *        created certificate. Currently no additional parameters in requests are considered!
     *        Currently no additional parameters in the PKCS10 request is considered!
     * @param responseClass The implementation class that will be used as the response message.
     *
     * @return The newly created response message or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws SignRequestException if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *         the CA.
     * @throws RemoteException if a communication or other error occurs.
     *
     * @see se.anatom.ejbca.protocol.IRequestMessage
     */
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, Class responseClass)
        throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException;

    /**
     * Requests for a certificate to be created for the passed public key wrapped in a
     * certification request message (ex PKCS10).  The username and password used to authorize is
     * taken from the request message. Verification of the signature (proof-of-possesion) on the
     * request is performed, and an exception thrown if verification fails. The method queries the
     * user database for authorization of the user.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param req a Certification Request message, containing the public key to be put in the
     *        created certificate. Currently no additional parameters in requests are considered!
     * @param keyUsage integer with bit mask describing desired keys usage. Bit mask is packed in
     *        in integer using contants from CertificateData. ex. int keyusage =
     *        CertificateData.digitalSignature | CertificateData.nonRepudiation; gives
     *        digitalSignature and nonRepudiation. ex. int keyusage = CertificateData.keyCertSign
     *        | CertificateData.cRLSign; gives keyCertSign and cRLSign. Keyusage < 0 means that default 
     *        keyUsage should be used.
     * @param responseClass The implementation class that will be used as the response message.
     *
     * @return The newly created response or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws CADoesntExistsException if the targeted CA does not exist
     * @throws SignRequestException if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *         the CA.
     * @throws RemoteException if a communication or other error occurs.
     *
     * @see se.anatom.ejbca.ca.store.CertificateData
     * @see se.anatom.ejbca.protocol.IRequestMessage
     * @see se.anatom.ejbca.protocol.IResponseMessage
     * @see se.anatom.ejbca.protocol.X509ResponseMessage
     */
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, int keyUsage,
        Class responseClass)
        throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, 
            IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException;

    /**
     * Requests for a CRL to be sent back in the requested response format (ex SCEP).  
     * The information used to find out which CRL is taken from the request message. 
     * Verification of the signature (proof-of-possesion) on the request is performed, 
     * and an exception thrown if verification fails. 
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param req a CRL Request message
     * @param responseClass The implementation class that will be used as the response message.
     *
     * @return The newly created response or null.
     *
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws IllegalKeyException if the public key is of wrong type.
     * @throws CADoesntExistsException if the targeted CA does not exist
     * @throws SignRequestException if the provided request is invalid.
     * @throws SignRequestSignatureException if the provided client certificate was not signed by
     *         the CA.
     * @throws RemoteException if a communication or other error occurs.
     *
     * @see se.anatom.ejbca.ca.store.CertificateData
     * @see se.anatom.ejbca.protocol.IRequestMessage
     * @see se.anatom.ejbca.protocol.IResponseMessage
     * @see se.anatom.ejbca.protocol.X509ResponseMessage
     */
    public IResponseMessage getCRL(Admin admin, IRequestMessage req, Class responseClass)
        throws RemoteException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException;

    /**
	 * Requests for a CRL to be created with the passed (revoked) certificates.
	 *
	 * @param admin Information about the administrator or admin preforming the event.
	 * @param certs vector of RevokedCertInfo object.
	 *
	 * @return The newly created CRL or null.
	 *
	 * @throws RemoteException if a communication or other error occurs.
	 */
    public X509CRL createCRL(Admin admin, int caid, Vector certs) throws RemoteException;
    
    /**
     * Method used to perform a extended CA Service, like OCSP CA Service.
     * 
     * 
     * @param admin Information about the administrator or admin preforming the event. 
     * @param caid the ca that should perform the service
     * @param request a service request.
     * @return A corresponding response.
     * @throws IllegalExtendedCAServiceRequestException if the request was invalid.
     * @throws ExtendedCAServiceNotActiveException thrown when the service for the given CA isn't activated
     * @throws CADoesntExistsException The given caid doesn't exists.
     */
    
	public ExtendedCAServiceResponse extendedService(Admin admin, int caid, ExtendedCAServiceRequest request) 
	  throws RemoteException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, CADoesntExistsException;
    
    
   /**
    * Method that publishes the given CA certificate chain to the list of publishers.
    * Is mainly used by CAAdminSessionBean when CA is created.
    * 
    *  @param admin Information about the administrator or admin preforming the event.
    *  @param certificatechain certchain of certificate to publish
    *  @param publishers a collection if publisher id's (Integer) indicating which publisher that should be used.
    *  @param certtype is one of SecConst.CERTTYPE_ constants
    */
    public void publishCACertificate(Admin admin, Collection certificatechain, Collection publishers, int certtype) throws RemoteException;
    
}



