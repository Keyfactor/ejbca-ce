

package se.anatom.ejbca.ca.sign;



import java.util.Vector;

import java.rmi.RemoteException;

import javax.ejb.ObjectNotFoundException;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.PublicKey;

import se.anatom.ejbca.ca.exception.AuthStatusException;
import se.anatom.ejbca.ca.exception.AuthLoginException;
import se.anatom.ejbca.ca.exception.SignRequestException;
import se.anatom.ejbca.ca.exception.SignRequestSignatureException;
import se.anatom.ejbca.ca.exception.IllegalKeyException;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;
import se.anatom.ejbca.log.Admin;

/** Creates certificates.
 * Remote interface for EJB.
 *
 * @version $Id: ISignSessionRemote.java,v 1.13 2003-06-11 13:28:08 anatom Exp $
 */
public interface ISignSessionRemote extends javax.ejb.EJBObject {

   /**
    * Retrieves the certificate chain for the signer.
    * The returned certificate chain MUST have the RootCA certificate in the last position.
    *
    * @param admin Information about the administrator or admin preforming the event.
    * @return The certificate chain, never null.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate[] getCertificateChain(Admin admin) throws RemoteException;

    /**
     * Creates a signed PKCS7 message containing the whole certificate chain, including the provided client certificate.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param cert client certificate which we want ancapsulated in a PKCS7 together with certificate chain. If null, a PKCS7 with only CA certificate chain is returned.
     * @return The DER-encoded PCS7 message.
     * @throws SignRequestSignatureException is the provided client certificate was not signed by the CA.
     * @throws EJBException if a communication or other error occurs.
     */
    public byte[] createPKCS7(Admin admin, Certificate cert) throws RemoteException, SignRequestSignatureException;

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
    * @throws ObjectNotFoundException if the user does not exist.
    * @throws AuthStatusException If the users status is incorrect.
    * @throws AuthLoginException If the password is incorrect.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk) throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException;

   /**
    * Requests for a certificate to be created for the passed public key with the passed key usage.
    * The method queries the user database for authorization of the user. CAs are only allowed to have
    * certificateSign and CRLSign set.
    *
    * @param admin Information about the administrator or admin preforming the event.
    * @param username unique username within the instance.
    * @param password password for the user.
    * @param pk the public key to be put in the created certificate.
    * @param keyusage integer with mask describing desired key usage in format specified by X509Certificate.getKeyUsage().
    *
    * id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
    *
    * KeyUsage ::= BIT STRING {
    *     digitalSignature        (0),
    *     nonRepudiation          (1),
    *     keyEncipherment         (2),
    *     dataEncipherment        (3),
    *     keyAgreement            (4),
    *     keyCertSign             (5),
    *     cRLSign                 (6),
    *     encipherOnly            (7),
    *     decipherOnly            (8) }
    *
    * @return The newly created certificate or null.
    * @throws ObjectNotFoundException if the user does not exist.
    * @throws AuthStatusException If the users status is incorrect.
    * @throws AuthLoginException If the password is incorrect.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, boolean[] keyusage) throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException;

   /**
    * Requests for a certificate to be created for the passed public key with the passed key usage.
    * The method queries the user database for authorization of the user. CAs are only allowed to have
    * certificateSign and CRLSign set.
    *
    * @param admin Information about the administrator or admin preforming the event.
    * @param username unique username within the instance.
    * @param password password for the user.
    * @param pk the public key to be put in the created certificate.
    * @param keyusage integer with bit mask describing desired keys usage, overrides keyUsage from CertificateProfiles if allowed. Bit mask is packed in in integer using constants from CertificateData. -1 means use default keyUsage from CertificateProfile.
    * ex. int keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives digitalSignature and nonRepudiation.
    * ex. int keyusage = CertificateData.keyCertSign | CertificateData.cRLSign; gives keyCertSign and cRLSign
    *
    * @see se.anatom.ejbca.ca.store.CertificateData
    *
    * @return The newly created certificate or null.
    * @throws ObjectNotFoundException if the user does not exist.
    * @throws AuthStatusException If the users status is incorrect.
    * @throws AuthLoginException If the password is incorrect.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(Admin admin,  String username, String password, PublicKey pk, int keyusage) throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException;

    /**
    * Requests for a certificate of the specified type to be created for the passed public key.
    * The method queries the user database for authorization of the user.
    *
    * @param admin Information about the administrator or admin preforming the event.
    * @param username unique username within the instance.
    * @param password password for the user.
    * @param certType integer type of certificate taken from CertificateData.CERT_TYPE_XXX.
    * the type CertificateData.CERT_TYPE_ENCRYPTION gives keyUsage keyEncipherment, dataEncipherment.
    * the type CertificateData.CERT_TYPE_SIGNATURE gives keyUsage digitalSignature, non-repudiation.
    * all other CERT_TYPES gives the default keyUsage digitalSignature, keyEncipherment
    * @param pk the public key to be put in the created certificate.
    *
    * @see se.anatom.ejbca.ca.store.CertificateData
    *
    * @return The newly created certificate or null.
    * @throws ObjectNotFoundException if the user does not exist.
    * @throws AuthStatusException If the users status is incorrect.
    * @throws AuthLoginException If the password is incorrect.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(Admin admin, String username, String password, int certType, PublicKey pk) throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException;

   /**
    * Requests for a certificate to be created for the passed public key wrapped in a self-signed certificate.
    * Verification of the signature (proof-of-possesion) on the request is performed, and an exception thrown if verification fails.
    * The method queries the user database for authorization of the user.
    *
    * @param admin Information about the administrator or admin preforming the event.
    * @param username unique username within the instance.
    * @param password password for the user.
    * @param incert a certificate containing the public key to be put in the created certificate.
    * Other (requested) parameters in the passed certificate can be used, such as DN, Validity, KeyUsage etc.
    * Currently only KeyUsage is considered!
    *
    * @return The newly created certificate or null.
    * @throws ObjectNotFoundException if the user does not exist.
    * @throws AuthStatusException If the users status is incorrect.
    * @throws AuthLoginException If the password is incorrect.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(Admin admin, String username, String password, Certificate incert) throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, SignRequestSignatureException;

   /**
    * Requests for a certificate to be created for the passed public key wrapped in a certification request message (ex PKCS10).
    * Verification of the signature (proof-of-possesion) on the request is performed, and an exception thrown if verification fails.
    * The method queries the user database for authorization of the user.
    *
    * @param admin Information about the administrator or admin preforming the event.
    * @param username unique username within the instance.
    * @param password password for the user.
    * @param req a Certification Request message, containing the public key to be put in the created certificate. Currently no additional parameters in requests are considered!
    * Currently no additional parameters in the PKCS10 request is considered!
    *
    * @see se.anatom.ejbca.protocol.IRequestMessage
    * 
    * @return The newly created certificate or null.
    * @throws ObjectNotFoundException if the user does not exist.
    * @throws AuthStatusException If the users status is incorrect.
    * @throws AuthLoginException If the password is incorrect.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(Admin admin, String username, String password, IRequestMessage req) throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, SignRequestException, SignRequestSignatureException;

   /**
    * Requests for a certificate to be created for the passed public key wrapped in a certification request message (ex PKCS10).
    * Verification of the signature (proof-of-possesion) on the request is performed, and an exception thrown if verification fails.
    * The method queries the user database for authorization of the user.
    *
    * @param admin Information about the administrator or admin preforming the event.
    * @param username unique username within the instance.
    * @param password password for the user.
    * @param req a Certification Request message, containing the public key to be put in the created certificate. Currently no additional parameters in requests are considered!
    * @param keyusage integer with bit mask describing desired keys usage. Bit mask is packed in in integer using contants from CertificateData.
    * ex. int keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives digitalSignature and nonRepudiation.
    * ex. int keyusage = CertificateData.keyCertSign | CertificateData.cRLSign; gives keyCertSign and cRLSign
    *
    * @see se.anatom.ejbca.ca.store.CertificateData
     * @see se.anatom.ejbca.protocol.IRequestMessage
    *
    * @return The newly created certificate or null.
    * @throws ObjectNotFoundException if the user does not exist.
    * @throws AuthStatusException If the users status is incorrect.
    * @throws AuthLoginException If the password is incorrect.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(Admin admin, String username, String password, IRequestMessage req, int keyUsage) throws RemoteException, ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, SignRequestException, SignRequestSignatureException;
    /**
     * Requests for a certificate to be created for the passed public key wrapped in a certification request message (ex PKCS10). 
     * The username and password used to authorize is taken from the request message.
     * Verification of the signature (proof-of-possesion) on the request is performed, and an exception thrown if verification fails.
     * The method queries the user database for authorization of the user.
     *
     * @param admin Information about the administrator or admin preforming the event.
     * @param req a Certification Request message, containing the public key to be put in the created certificate. Currently no additional parameters in requests are considered!
     * @param keyusage integer with bit mask describing desired keys usage. Bit mask is packed in in integer using contants from CertificateData.
     * ex. int keyusage = CertificateData.digitalSignature | CertificateData.nonRepudiation; gives digitalSignature and nonRepudiation.
     * ex. int keyusage = CertificateData.keyCertSign | CertificateData.cRLSign; gives keyCertSign and cRLSign
     * @param responseClass The class that will be used as the response message.
     *
     * @see se.anatom.ejbca.ca.store.CertificateData
     * @see se.anatom.ejbca.protocol.IRequestMessage
     * @see se.anatom.ejbca.protocol.IResponseMessage
     * @see se.anatom.ejbca.protocol.X509ResponseMessage
     *
     * @return The newly created response or null.
     * @throws ObjectNotFoundException if the user does not exist.
     * @throws AuthStatusException If the users status is incorrect.
     * @throws AuthLoginException If the password is incorrect.
     * @throws EJBException if a communication or other error occurs.
     */
    public IResponseMessage createCertificate(Admin admin, IRequestMessage req, int keyUsage, Class responseClass) throws ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException, SignRequestException, SignRequestSignatureException;

   /**
    * Requests for a CRL to be created with the passed (revoked) certificates.
    *
    * @param admin Information about the administrator or admin preforming the event.
    * @param certs vector of RevokedCertInfo object.
    *
    * @return The newly created CRL or null.
    * @throws EJBException if a communication or other error occurs.
    */
    public X509CRL createCRL(Admin admin, Vector certs) throws RemoteException;



}

