package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import java.security.cert.Certificate;
import java.util.Collection;

/**
 * For docs, see CertificateDataBean
 **/
public interface CertificateDataLocalHome extends javax.ejb.EJBLocalHome {

    public CertificateDataLocal create(Certificate incert)
        throws CreateException;

    public CertificateDataLocal findByPrimaryKey(CertificateDataPK pk)
        throws FinderException;

    /** Finds certificates which expire within a specified time.
     * @param expireTime (Date.getTime()-format), all certificates that expires before this date will be listed.
     * @return Collection of CertificateData in no specified order.
     */
    public Collection findByExpireDate(long expireDate)
        throws FinderException;
    /** Finds certificates which a specified subjectDN.
     * @param subjectDN, the subject whose certificates will be listed
     * @return Collection of CertificateData in no specified order.
     */
    public Collection findBySubjectDN(String subjectDN)
        throws FinderException;
    /** Finds the certificate which a specified issuerDN and SerialNumber.
     * @param issuerDN, the issuer of the certificates that is wanted.
     * @param serialNumber, the serial number (BigInteger.toString()-format) of the certificates that is wanted.
     * @return Collection of CertificateData in no specified order (should only contain one!).
     */
    public Collection findByIssuerDNSerialNumber(String issuerDN, String serialNumber)
        throws FinderException;
}
