
package se.anatom.ejbca.ca.store;

import java.util.Collection;
import java.util.Date;
import java.rmi.RemoteException;
import java.math.BigInteger;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;

/**
 * The CertificateStoreSession is the primary storage
 * for certificates and CRL. The CA always puts certificates and CRLs in the
 * CertificateStoreSession session bean defined in ca/ejb-jar.xml. The
 * CertificateStoreSession is also used to retrieve and find certificates,
 * retrieve CRLs, check for revocation etc. the CertificateStoreSession implements
 * the interface ICertificateStoreSession.
 *
 * @version $Id: ICertificateStoreSession.java,v 1.8 2002-05-26 11:12:12 anatom Exp $
 */
public interface ICertificateStoreSession extends IPublisherSession {

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
    * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection findCertificatesBySubject(String subjectDN) throws RemoteException;

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
    * Finds certificate which expire within a specified time.
    *
    * @param expireTime all certificates that expires before this date will be listed
    * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection findCertificatesByExpireTime(Date expireTime) throws RemoteException;

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
    * @return Collection of Strings containing fingerprint (primary key) of the revoced certificates. Reverse ordered by expireDate where last expireDate is first in array.
    * @throws EJBException if a communication or other error occurs.
    */
    public Collection listRevokedCertificates() throws RemoteException;

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
