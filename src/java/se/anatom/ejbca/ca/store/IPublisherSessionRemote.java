
package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;

/** Besides the CertificateStoreSession, certificates and CRLs can also be published
 * to any number of other certificate stores, which are defined by session beans
 * PublisherSession1, PublisherSession2, etc.
 * A PublisherSession is a simple subset of the CertificateStoreSession and
 * can only be used to store certificates and CRLs. PublisherSession's implement
 * the interface IPublisherSession.
 *
 * Remote interface for EJB.
 *
 * @version $Id: IPublisherSessionRemote.java,v 1.2 2002-06-04 14:37:07 anatom Exp $
 */
public interface IPublisherSessionRemote extends javax.ejb.EJBObject {

   /**
    * Publishes a certificate to a certificate store.
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
    * Published a CRL to a CRL store.
    *
    * @param incrl The DER coded CRL to be stored.
    * @param chainfp Fingerprint (hex) of the CAs certificate.
    * @param number CRL number.
    *
    * @return true if storage was succesful.
    * @throws EJBException if a communication or other error occurs.
    */
    public boolean storeCRL(byte[] incrl, String cafp, int number) throws RemoteException;

}
