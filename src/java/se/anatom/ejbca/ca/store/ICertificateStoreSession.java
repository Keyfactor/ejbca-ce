
package se.anatom.ejbca.ca.store;

import java.util.*;
import java.rmi.RemoteException;
import java.math.BigInteger;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;

/**
 *
 * @version $Id: ICertificateStoreSession.java,v 1.1.1.1 2001-11-15 14:58:16 anatom Exp $
 */
public interface ICertificateStoreSession {

   /**
    * Stores a certificate in the database.
    *
    * @param incert The certificate to be stored.
    * @param chainfp Fingerprint (hex) of the CAs certificate.
    * @param status Status of the certificate (from CertificateData).
    * @param type Type of certificate (from SecConst).
    *
    * @return true if storage was succesful.
    * @throws EJBException if a communication or other error occurs.
    */
    public boolean storeCertificate(Certificate incert, String cafp, int status, int type) throws RemoteException;

   /**
    * Stores a CRL in the database.
    *
    * @param incrl The CRL to be stored.
    * @param chainfp Fingerprint (hex) of the CAs certificate.
    * @param number CRL number.
    *
    * @return true if storage was succesful.
    * @throws EJBException if a communication or other error occurs.
    */
    public boolean storeCRL(X509CRL incrl, String cafp, int number) throws RemoteException;

   /**
    * Lists fingerprint (primary key) of ALL certificates in the database.
    * NOTE: Caution should be taken with this method as execution may be very
    * heavy indeed if many certificates exist in the database (imagine what happens if
    * there are millinos of certificates in the DB!).
    * Should only be used for testing purposes.
    *
    * @return Array of fingerprints (reverse) ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public String[] listAllCertificates() throws RemoteException;

   /**
    * Lists certificates for a given subject.
    *
    * @param subjectDN the DN of the subject whos certificates will be retrieved.
    * @return Array of Certificates (reverse) ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate[] findCertificatesBySubject(String subjectDN) throws RemoteException;

   /**
    * Finds certificate for a given issuer and serialnumber.
    *
    * @param issuerDN the DN of the issuer.
    * @param serno the serialnumber of the certificate that will be retrieved
    * @return Certificate or null if none found.
    * @throws EJBException if a communication or other error occurs.
    */
    public Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno) throws RemoteException;

   /**
    * Checks if a certificate is revoked.
    *
    * @param issuerDN the DN of the issuer.
    * @param serno the serialnumber of the certificate that will be checked
    * @return null if certificate is NOT revoked, RevokedCertInfo if it IS revoked.
    * @throws EJBException if a communication or other error occurs.
    */
    public RevokedCertInfo isRevoked(String issuerDN, BigInteger serno) throws RemoteException;

    /**
    * Lists all revoked certificates, ie status = CERT_REVOKED.
    *
    * @return Array of Strings containing fingerprint (primary key) of the revoced certificates. Reverse ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public String[] listRevokedCertificates() throws RemoteException;

   /**
    * Retrieves the latest CRL issued by this CA.
    *
    * @return X509CRL or null of no CRLs have been issued.
    * @throws EJBException if a communication or other error occurs.
    */
    public byte[] getLastCRL() throws RemoteException;

   /**
    * Retrieves the highest CRLNumber issued by the CA.
    *
    * @return int.
    * @throws EJBException if a communication or other error occurs.
    */
    public int getLastCRLNumber() throws RemoteException;
}
