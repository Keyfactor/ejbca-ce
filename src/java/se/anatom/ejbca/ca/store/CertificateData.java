
package se.anatom.ejbca.ca.store;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Date;

import java.rmi.RemoteException;

/**
 * For docs, see CertificateDataBean
 **/
public interface CertificateData extends javax.ejb.EJBObject {

    // Constants for Status of certificate
    /** Certificate doesn't belong to anyone */
    public static int CERT_UNASSIGNED =      0;
    /** Assigned, but not yet active */
    public static int CERT_INACTIVE =        10;
    /** Certificate is active and assigned */
    public static int CERT_ACTIVE =          20;
    /** Certificate is temporarily blocked (reversible) */
    public static int CERT_TEMP_REVOKED =    30;
    /** Certificate is permanently blocked (terminated) */
    public static int CERT_REVOKED =         40;
    /** Certificate is expired */
    public static int CERT_EXPIRED =         50;
    /** Certificate is expired and kept for archive purpose */
    public static int CERT_ARCHIVED =        60;

    // Certificate types used to create certificates
    /** Certificate used for encryption. */
    public static final int CERT_TYPE_ENCRYPTION    = 0x1;
    /** Certificate used for digital signatures. */
    public static final int CERT_TYPE_SIGNATURE     = 0x2;
    /** Certificate used for both encryption and signatures. */
    public static final int CERT_TYPE_ENCSIGN       = 0x3;

    // Constants used to contruct KeyUsage
    /** @see se.anatom.ejbca.ca.sign.ISignSession */
    public static final int        digitalSignature = (1 << 7);
    public static final int        nonRepudiation   = (1 << 6);
    public static final int        keyEncipherment  = (1 << 5);
    public static final int        dataEncipherment = (1 << 4);
    public static final int        keyAgreement     = (1 << 3);
    public static final int        keyCertSign      = (1 << 2);
    public static final int        cRLSign          = (1 << 1);
    public static final int        encipherOnly     = (1 << 0);
    public static final int        decipherOnly     = (1 << 15);

    // public methods
    public String getSubjectDN() throws RemoteException;
    public void setSubjectDN(String subjectDN) throws RemoteException;
    public String getIssuerDN() throws RemoteException;
    public void setIssuerDN(String issuerDN) throws RemoteException;
    public BigInteger getSerialNumber() throws RemoteException;
    public void setSerialNumber(BigInteger serialNumber) throws RemoteException;
    public String getFingerprint() throws RemoteException;
    public void setFingerprint(String fingerprint) throws RemoteException;
    public String getCAFingerprint() throws RemoteException;
    public void setCAFingerprint(String cAFingerorint) throws RemoteException;
    public int getStatus() throws RemoteException;
    public void setStatus(int status) throws RemoteException;
    public int getType() throws RemoteException;
    public void setType(int type) throws RemoteException;
    public Date getExpireDate() throws RemoteException;
    public void setExpireDate(Date expireDate) throws RemoteException;
    public Date getRevocationDate() throws RemoteException;
    public void setRevocationDate(Date revocationDate) throws RemoteException;
    public int getRevocationReason() throws RemoteException;
    public void setRevocationReason(int revocationReason) throws RemoteException;
    public String getBase64Cert() throws RemoteException;
    public void setBase64Cert(String base64Cert) throws RemoteException;

    public Certificate getCertificate() throws RemoteException;
    public void setCertificate(Certificate certificate) throws RemoteException;
    public void setIssuer(String dn) throws RemoteException;
    public void setSubject(String dn) throws RemoteException;
    
}
