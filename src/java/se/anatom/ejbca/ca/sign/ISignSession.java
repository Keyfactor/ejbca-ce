
package se.anatom.ejbca.ca.sign;

import java.util.*;
import java.rmi.RemoteException;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.PublicKey;

/**
 * Creates certificates.
 *
 * @version $Id: ISignSession.java,v 1.1.1.1 2001-11-15 14:58:14 anatom Exp $
 */
public interface ISignSession {

   /**
    * Retrieves the certificate chainfor the signer.
    * The returned certificate chain MUST have the RootCA certificate in the last position.
    *
    *
    * @return The certificate chain, never null.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate[] getCertificateChain() throws RemoteException;

   /**
    * Requests for a certificate to be created for the passed public key with default key usage
    * The method queries the user database for authorization of the user.
    *
    * @param username unique username within the instance.
    * @param password password for the user.
    * @param pk the public key to be put in the created certificate.
    *
    * @return The newly created certificate or null.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(String username, String password, PublicKey pk) throws RemoteException;

   /**
    * Requests for a certificate to be created for the passed public key with the passed key usage.
    * The method queries the user database for authorization of the user.
    *
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
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(String username, String password, PublicKey pk, boolean[] keyusage) throws RemoteException;

   /**
    * Requests for a certificate to be created for the passed public key wrapped in a self-signed certificate.
    * Verification of the signature (proof-of-possesion) on the request is performed, and an exception thrown if verification fails.
    * The method queries the user database for authorization of the user.
    *
    * @param username unique username within the instance.
    * @param password password for the user.
    * @param incert a certificate containing the public key to be put in the created certificate.
    * Other (requested) parameters in the passed certificate can be used, such as DN, Validity, KeyUsage etc.
    * Currently only KeyUsage is considered!
    *
    * @return The newly created certificate or null.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(String username, String password, Certificate incert) throws RemoteException;

   /**
    * Requests for a certificate to be created for the passed public key wrapped in a PKCS10 certification request.
    * Verification of the signature (proof-of-possesion) on the request is performed, and an exception thrown if verification fails.
    * The method queries the user database for authorization of the user.
    *
    * @param username unique username within the instance.
    * @param password password for the user.
    * @param req a PKCS10 Certification Request in DER format, containing the public key to be put in the created certificate.
    * Currently no additional parameters in the PKCS10 request is considered!
    *
    * @return The newly created certificate or null.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate createCertificate(String username, String password, byte[] pkcs10req) throws RemoteException;

   /**
    * Requests for a CRL to be created with the passed (revoked) certificates.
    *
    * @param certs vector of RevokedCertInfo object.
    *
    * @return The newly created CRL or null.
    * @throws EJBException if a communication or other error occurs.
    */
    public X509CRL createCRL(Vector certs) throws RemoteException;
}
