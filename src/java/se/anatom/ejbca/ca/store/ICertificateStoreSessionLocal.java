
package se.anatom.ejbca.ca.store;

import java.util.Collection;
import java.util.Date;
import java.math.BigInteger;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;

import se.anatom.ejbca.ca.crl.RevokedCertInfo;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: ICertificateStoreSessionLocal.java,v 1.2 2002-05-26 14:25:59 anatom Exp $
 * @see se.anatom.ejbca.ca.store.ICertificateStoreSession
 */
public interface ICertificateStoreSessionLocal extends javax.ejb.EJBLocalObject, IPublisherSessionLocal
{
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSession
     */ 
    public Collection listAllCertificates();
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSession
     */ 
    public Collection findCertificatesBySubject(String subjectDN);
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSession
     */ 
    public Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno);
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSession
     */ 
    public Collection findCertificatesByExpireTime(Date expireTime);
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSession
     */ 
    public RevokedCertInfo isRevoked(String issuerDN, BigInteger serno);
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSession
     */ 
    public Collection listRevokedCertificates();
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSession
     */ 
    public byte[] getLastCRL();
    /**
     * @see se.anatom.ejbca.ca.store.ICertificateStoreSession
     */ 
    public int getLastCRLNumber();

}
