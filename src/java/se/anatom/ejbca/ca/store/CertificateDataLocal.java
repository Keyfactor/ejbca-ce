package se.anatom.ejbca.ca.store;

import java.security.cert.Certificate;

import java.util.Date;


/**
 * For docs, see CertificateDataBean
 */
public interface CertificateDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public String getSubjectDN();

    /**
     * DN of issuer of certificate
     *
     * @return issuer dn
     */
    public String getIssuerDN();

    /**
     * Serialnumber formated as BigInteger.toString()
     *
     * @return serial number
     */
    public String getSerialNumber();

    /**
     * Serialnumber formated as BigInteger.toString()
     *
     * @param serialNumber serial number
     */
    public void setSerialNumber(String serialNumber);

    /**
     * Fingerprint of certificate
     *
     * @return fingerprint
     */
    public String getFingerprint();

    /**
     * Fingerprint of certificate
     *
     * @param fingerprint fingerprint
     */
    public void setFingerprint(String fingerprint);

    /**
     * Fingerprint of CA certificate
     *
     * @return fingerprint
     */
    public String getCAFingerprint();

    /**
     * Fingerprint of CA certificate
     *
     * @param cAFingerprint fingerprint
     */
    public void setCAFingerprint(String cAFingerprint);

    /**
     * Status of certificate
     *
     * @return status
     */
    public int getStatus();

    /**
     * Status of certificate
     *
     * @param status status
     */
    public void setStatus(int status);

    /**
     * Type of certificate
     *
     * @return Type of certificate
     */
    public int getType();

    /**
     * Type of certificate
     *
     * @param type type
     */
    public void setType(int type);

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @return expire date
     */
    public long getExpireDate();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @param expireDate expire date
     */
    public void setExpireDate(long expireDate);

    /**
     * Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime()
     *
     * @return revocation date
     */
    public long getRevocationDate();

    /**
     * Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime()
     *
     * @param revocationDate revocation date
     */
    public void setRevocationDate(long revocationDate);

    /**
     * Reason for revocation of cert
     *
     * @return revocation reason
     */
    public int getRevocationReason();

    /**
     * Reason for revocation of cert
     *
     * @param revocationReason revocation reason
     */
    public void setRevocationReason(int revocationReason);

    /**
     * base64 encoded certificate
     *
     * @return base64 encoded certificate
     */
    public String getBase64Cert();

    /**
     * base64 encoded certificate
     *
     * @param base64Cert base64 encoded certificate
     */
    public void setBase64Cert(String base64Cert);

    /**
     * username
     *
     * @return username
     */
    public String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @param username username
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public void setUsername(String username);

    // Public helper methods, not directly related to persistance

    /**
     * certificate itself
     *
     * @return certificate
     */
    public Certificate getCertificate();

    /**
     * certificate itself
     *
     * @param certificate certificate
     */
    public void setCertificate(Certificate certificate);

    /**
     * DN of issuer of certificate
     *
     * @param dn issuer dn
     */
    public void setIssuer(String dn);

    /**
     * DN of subject of certificate
     *
     * @param dn issuer dn
     */
    public void setSubject(String dn);

    /**
     * date the certificate expires
     *
     * @param expireDate expire date
     */
    public void setExpireDate(Date expireDate);

    /**
     * date the certificate was revoked
     *
     * @param revocationDate revocation date
     */
    public void setRevocationDate(Date revocationDate);
}
