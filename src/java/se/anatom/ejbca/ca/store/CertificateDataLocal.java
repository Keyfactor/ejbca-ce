
package se.anatom.ejbca.ca.store;

import java.security.cert.Certificate;
import java.util.Date;

/**
 * For docs, see CertificateDataBean
 **/
public interface CertificateDataLocal extends javax.ejb.EJBLocalObject {

    // public methods
    public String getSubjectDN();
    public String getIssuerDN();
    public String getSerialNumber();
    public void setSerialNumber(String serialNumber);
    public String getFingerprint();
    public void setFingerprint(String fingerprint);
    public String getCAFingerprint();
    public void setCAFingerprint(String cAFingerorint);
    public int getStatus();
    public void setStatus(int status);
    public int getType();
    public void setType(int type);
    public long getExpireDate();
    public void setExpireDate(long expireDate);
    public long getRevocationDate();
    public void setRevocationDate(long revocationDate);
    public int getRevocationReason();
    public void setRevocationReason(int revocationReason);
    public String getBase64Cert();
    public void setBase64Cert(String base64Cert);

    // Public helper methods, not directly related to persistance
    public Certificate getCertificate();
    public void setCertificate(Certificate certificate);
    public void setIssuer(String dn);
    public void setSubject(String dn);
    public void setExpireDate(Date expireDate);
    public void setRevocationDate(Date revocationDate);
}
