package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;

import java.security.cert.Certificate;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see CertificateDataBean
 */
public interface CertificateDataHome extends javax.ejb.EJBHome {
    /**
     * cretaes a new certificate in the DB
     *
     * @param incert certificate
     *
     * @return data certificate object
     *
     * @throws CreateException if object can not be created in db
     * @throws RemoteException communication or other error
     */
    public CertificateData create(Certificate incert) throws CreateException, RemoteException;

    /**
     * finds a certificate in db
     *
     * @param pk primare key
     *
     * @return certificate object
     *
     * @throws FinderException if certificate can not be found
     * @throws RemoteException communication or other error
     */
    public CertificateData findByPrimaryKey(CertificateDataPK pk)
        throws FinderException, RemoteException;

    /**
     * Finds certificates which expire within a specified time.
     *
     * @param expireTime (Date.getTime()-format), all certificates that expires before this date
     *        will be listed.
     *
     * @return Collection of CertificateData in no specified order.
     *
     * @throws FinderException if certificate can not be found
     * @throws RemoteException communication or other error
     */
    public Collection findByExpireDate(long expireDate)
        throws FinderException, RemoteException;

    /**
     * Finds certificates which a specified subjectDN.
     *
     * @param subjectDN , the subject whose certificates will be listed
     *
     * @return Collection of CertificateData in no specified order.
     *
     * @throws FinderException if certificate can not be found
     * @throws RemoteException communication or other error
     */
    public Collection findBySubjectDN(String subjectDN)
        throws FinderException, RemoteException;

    /**
     * Finds the certificate which a specified issuerDN and SerialNumber.
     *
     * @param issuerDN , the issuer of the certificates that is wanted.
     * @param serialNumber , the serial number (BigInteger.toString()-format) of the certificates
     *        that is wanted.
     *
     * @return Collection of CertificateData in no specified order (should only contain one!).
     *
     * @throws FinderException if certificate can not be found
     * @throws RemoteException communication or other error
     */
    public Collection findByIssuerDNSerialNumber(String issuerDN, String serialNumber)
        throws FinderException, RemoteException;

    /**
     * Finds the certificate which a specified SerialNumber.
     *
     * @param serialNumber , the serial number (BigInteger.toString()-format) of the certificates
     *        that is wanted.
     *
     * @return Collection of CertificateData in no specified order (should only contain one!).
     *
     * @throws FinderException if certificate can not be found
     * @throws RemoteException communication or other error
     */
    public Collection findBySerialNumber(String serialNumber)
        throws FinderException, RemoteException;

    /**
     * Finds the certificate which a specified Username.
     *
     * @param username of the certificates that is wanted.
     *
     * @return Collection of CertificateData in no specified order (should only contain one!).
     *
     * @throws FinderException if certificate can not be found
     * @throws RemoteException communication or other error
     */
    public Collection findByUsername(String username) throws FinderException, RemoteException;
}
