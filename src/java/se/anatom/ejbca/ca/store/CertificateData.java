package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;

import java.security.cert.Certificate;

import java.util.Date;


/**
 * For docs, see CertificateDataBean
 *
 * @see se.anatom.ejbca.ca.store.CertificateDataBean
 */
public interface CertificateData extends javax.ejb.EJBObject {
    // Constants for Status of certificate

    /** Certificate doesn't belong to anyone */
    public static int CERT_UNASSIGNED = 0;

    /** Assigned, but not yet active */
    public static int CERT_INACTIVE = 10;

    /** Certificate is active and assigned */
    public static int CERT_ACTIVE = 20;

    /** Certificate is temporarily blocked (reversible) */
    public static int CERT_TEMP_REVOKED = 30;

    /** Certificate is permanently blocked (terminated) */
    public static int CERT_REVOKED = 40;

    /** Certificate is expired */
    public static int CERT_EXPIRED = 50;

    /** Certificate is expired and kept for archive purpose */
    public static int CERT_ARCHIVED = 60;

    // Certificate types used to create certificates

    /** Certificate used for encryption. */
    public static final int CERT_TYPE_ENCRYPTION = 0x1;

    /** Certificate used for digital signatures. */
    public static final int CERT_TYPE_SIGNATURE = 0x2;

    /** Certificate used for both encryption and signatures. */
    public static final int CERT_TYPE_ENCSIGN = 0x3;

    // Constants used to contruct KeyUsage

    /**
     * @see se.anatom.ejbca.ca.sign.ISignSessionRemote
     */
    public static final int digitalSignature = (1 << 7);
    public static final int nonRepudiation = (1 << 6);
    public static final int keyEncipherment = (1 << 5);
    public static final int dataEncipherment = (1 << 4);
    public static final int keyAgreement = (1 << 3);
    public static final int keyCertSign = (1 << 2);
    public static final int cRLSign = (1 << 1);
    public static final int encipherOnly = (1 << 0);
    public static final int decipherOnly = (1 << 15);

    // public methods
    public String getSubjectDN() throws RemoteException;

    /**
     * getter
     *
     * @return dn
     *
     * @throws RemoteException error
     */
    public String getIssuerDN() throws RemoteException;

    /**
     * getter
     *
     * @return serial number
     *
     * @throws RemoteException error
     */
    public String getSerialNumber() throws RemoteException;

    /**
     * setter
     *
     * @param serialNumber serial number
     *
     * @throws RemoteException error
     */
    public void setSerialNumber(String serialNumber) throws RemoteException;

    /**
     * getter
     *
     * @return fingerprint
     *
     * @throws RemoteException error
     */
    public String getFingerprint() throws RemoteException;

    /**
     * setter
     *
     * @param fingerprint fingerprint
     *
     * @throws RemoteException error
     */
    public void setFingerprint(String fingerprint) throws RemoteException;

    /**
     * getter
     *
     * @return fingerprint
     *
     * @throws RemoteException error
     */
    public String getCAFingerprint() throws RemoteException;

    /**
     * setter
     *
     * @param cAFingerprint fingerprint
     *
     * @throws RemoteException error
     */
    public void setCAFingerprint(String cAFingerprint)
        throws RemoteException;

    /**
     * getter
     *
     * @return status
     *
     * @throws RemoteException error
     */
    public int getStatus() throws RemoteException;

    /**
     * setter
     *
     * @param status status
     *
     * @throws RemoteException error
     */
    public void setStatus(int status) throws RemoteException;

    /**
     * getter
     *
     * @return type
     *
     * @throws RemoteException error
     */
    public int getType() throws RemoteException;

    /**
     * setter
     *
     * @param type type
     *
     * @throws RemoteException error
     */
    public void setType(int type) throws RemoteException;

    /**
     * getter
     *
     * @return expire date
     *
     * @throws RemoteException error
     */
    public long getExpireDate() throws RemoteException;

    /**
     * setter
     *
     * @param expireDate expire date
     *
     * @throws RemoteException error
     */
    public void setExpireDate(long expireDate) throws RemoteException;

    /**
     * getter
     *
     * @return revocation date
     *
     * @throws RemoteException error
     */
    public long getRevocationDate() throws RemoteException;

    /**
     * setter
     *
     * @param revocationDate revocation date
     *
     * @throws RemoteException error
     */
    public void setRevocationDate(long revocationDate)
        throws RemoteException;

    /**
     * getter
     *
     * @return revocation reason
     *
     * @throws RemoteException error
     */
    public int getRevocationReason() throws RemoteException;

    /**
     * setter
     *
     * @param revocationReason revocation reason
     *
     * @throws RemoteException error
     */
    public void setRevocationReason(int revocationReason)
        throws RemoteException;

    /**
     * getter
     *
     * @return base64 encoded cert
     *
     * @throws RemoteException error
     */
    public String getBase64Cert() throws RemoteException;

    /**
     * setter
     *
     * @param base64Cert base64 encoded cert
     *
     * @throws RemoteException error
     */
    public void setBase64Cert(String base64Cert) throws RemoteException;

    /**
     * getter
     *
     * @return username
     *
     * @throws RemoteException error
     */
    public String getUsername() throws RemoteException;

    /**
     * setter
     *
     * @param username username
     *
     * @throws RemoteException error
     */
    public void setUsername(String username) throws RemoteException;

    // Public helper methods, not directly related to persistance
    public Certificate getCertificate() throws RemoteException;

    /**
     * getter
     *
     * @param certificate certificate
     *
     * @throws RemoteException error
     */
    public void setCertificate(Certificate certificate)
        throws RemoteException;

    /**
     * setter
     *
     * @param dn issuer dn
     *
     * @throws RemoteException error
     */
    public void setIssuer(String dn) throws RemoteException;

    /**
     * setter
     *
     * @param dn subject dn
     *
     * @throws RemoteException error
     */
    public void setSubject(String dn) throws RemoteException;

    /**
     * setter
     *
     * @param expireDate expire date
     *
     * @throws RemoteException error
     */
    public void setExpireDate(Date expireDate) throws RemoteException;

    /**
     * setter
     *
     * @param revocationDate revocation date
     *
     * @throws RemoteException error
     */
    public void setRevocationDate(Date revocationDate)
        throws RemoteException;
}
