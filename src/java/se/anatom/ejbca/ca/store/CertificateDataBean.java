package se.anatom.ejbca.ca.store;

import java.io.IOException;
import java.security.cert.*;
import java.util.Date;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;


/**
 * Entity Bean representing a certificate. Information stored:
 * <pre>
 * Certificate (base64Cert)
 * Subject DN (subjectDN)
 * Issuer DN (issuerDN)
 * Serial number (serialNumber)
 * SHA1 fingerprint (fingerprint)
 * Status (status)
 * Type (type, from SecConst)
 * CA SHA1 fingerprint (cAFingerprint)
 * Expiration date (expireDate)
 * Revocation date (revocationDate)
 * Revocation reason (revocationReason)
 * Username (username)
 * </pre>
 *
 * @version $Id: CertificateDataBean.java,v 1.23 2003-09-11 06:59:57 anatom Exp $
 */
public abstract class CertificateDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(CertificateDataBean.class);

    /**
     * DN of issuer of certificate
     *
     * @return issuer dn
     */
    public abstract String getIssuerDN();

    /**
     * Use setIssuer instead
     *
     * @param issuerDN issuer dn
     *
     * @see #setIssuer(String)
     */
    public abstract void setIssuerDN(String issuerDN);

    /**
     * DN of subject in certificate
     *
     * @return subject dn
     */
    public abstract String getSubjectDN();

    /**
     * Use setSubject instead
     *
     * @param subjectDN subject dn
     *
     * @see #setSubject(String)
     */
    public abstract void setSubjectDN(String subjectDN);

    /**
     * Fingerprint of certificate
     *
     * @return fingerprint
     */
    public abstract String getFingerprint();

    /**
     * Fingerprint of certificate
     *
     * @param fingerprint fingerprint
     */
    public abstract void setFingerprint(String fingerprint);

    /**
     * Fingerprint of CA certificate
     *
     * @return fingerprint
     */
    public abstract String getCAFingerprint();

    /**
     * Fingerprint of CA certificate
     *
     * @param cAFingerprint fingerprint
     */
    public abstract void setCAFingerprint(String cAFingerprint);

    /**
     * status of certificate, ex CertificateData.CERT_ACTIVE
     *
     * @return status
     */
    public abstract int getStatus();

    /**
     * status of certificate, ex CertificateData.CERT_ACTIVE
     *
     * @param status status
     */
    public abstract void setStatus(int status);

    /**
     * What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
     *
     * @return user type
     */
    public abstract int getType();

    /**
     * What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
     *
     * @param type type
     */
    public abstract void setType(int type);

    /**
     * Serialnumber formated as BigInteger.toString()
     *
     * @return serial number
     */
    public abstract String getSerialNumber();

    /**
     * Serialnumber formated as BigInteger.toString()
     *
     * @param serialNumber serial number
     */
    public abstract void setSerialNumber(String serialNumber);

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @return expire date
     */
    public abstract long getExpireDate();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @param expireDate expire date
     */
    public abstract void setExpireDate(long expireDate);

    /**
     * Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime()
     *
     * @return revocation date
     */
    public abstract long getRevocationDate();

    /**
     * Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime()
     *
     * @param revocationDate revocation date
     */
    public abstract void setRevocationDate(long revocationDate);

    /**
     * Set to revocation reason if status== CERT_REVOKED
     *
     * @return revocation reason
     */
    public abstract int getRevocationReason();

    /**
     * Set to revocation reason if status== CERT_REVOKED
     *
     * @param revocationReason revocation reason
     */
    public abstract void setRevocationReason(int revocationReason);

    /**
     * certificate itself
     *
     * @return base64 encoded certificate
     */
    public abstract String getBase64Cert();

    /**
     * certificate itself
     *
     * @param base64Cert base64 encoded certificate
     */
    public abstract void setBase64Cert(String base64Cert);

    /**
     * username in database
     *
     * @return username
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @param username username
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public abstract void setUsername(String username);

    //
    // Public business methods used to help us manage certificates
    //

    /**
     * certificate itself
     *
     * @return certificate
     */
    public Certificate getCertificate() {
        X509Certificate cert = null;

        try {
            cert = CertTools.getCertfromByteArray(Base64.decode(getBase64Cert().getBytes()));
        } catch (IOException ioe) {
            log.error("Can't decode certificate.", ioe);

            return null;
        } catch (CertificateException ce) {
            log.error("Can't decode certificate.", ce);

            return null;
        }

        return cert;
    }

    /**
     * certificate itself
     *
     * @param incert certificate
     */
    public void setCertificate(Certificate incert) {
        try {
            String b64Cert = new String(Base64.encode(incert.getEncoded()));
            setBase64Cert(b64Cert);

            X509Certificate tmpcert = (X509Certificate) incert;
            String fp = CertTools.getFingerprintAsString(tmpcert);
            setFingerprint(fp);
            setSubjectDN(CertTools.getSubjectDN(tmpcert));
            setIssuerDN(CertTools.getIssuerDN(tmpcert));
            setSerialNumber(tmpcert.getSerialNumber().toString());
        } catch (CertificateEncodingException cee) {
            log.error("Can't extract DER encoded certificate information.", cee);
        }
    }

    /**
     * DN of issuer of certificate
     *
     * @param dn issuer dn
     */
    public void setIssuer(String dn) {
        setIssuerDN(CertTools.stringToBCDNString(dn));
    }

    /**
     * DN of subject in certificate
     *
     * @param dn subject dn
     */
    public void setSubject(String dn) {
        setSubjectDN(CertTools.stringToBCDNString(dn));
    }

    /**
     * expire date of certificate
     *
     * @param expireDate expire date
     */
    public void setExpireDate(Date expireDate) {
        if (expireDate == null) {
            setExpireDate(-1L);
        } else {
            setExpireDate(expireDate.getTime());
        }
    }

    /**
     * date the certificate was revoked
     *
     * @param revocationDate revocation date
     */
    public void setRevocationDate(Date revocationDate) {
        if (revocationDate == null) {
            setRevocationDate(-1L);
        } else {
            setRevocationDate(revocationDate.getTime());
        }
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a certficate. Create by sending in the certificate, which
     * extracts (from the cert) fingerprint (primary key), subjectDN, issuerDN, serial number,
     * expiration date. Status, Type, CAFingerprint, revocationDate and revocationReason are set
     * to default values (CERT_UNASSIGNED, USER_INVALID, null, null and
     * REVOKATION_REASON_UNSPECIFIED) and should be set using the respective set-methods.
     *
     * @param incert the (X509)Certificate to be stored in the database.
     *
     * @return primary key
     */
    public CertificateDataPK ejbCreate(Certificate incert)
        throws CreateException {
        // Exctract all fields to store with the certificate.
        X509Certificate tmpcert;

        try {
            String b64Cert = new String(Base64.encode(incert.getEncoded()));
            setBase64Cert(b64Cert);
            tmpcert = (X509Certificate) incert;

            String fp = CertTools.getFingerprintAsString(tmpcert);
            setFingerprint(fp);

            // Make sure names are always looking the same
            setSubjectDN(CertTools.getSubjectDN(tmpcert));
            setIssuerDN(CertTools.getIssuerDN(tmpcert));
            log.debug("Creating certdata, subject=" + getSubjectDN() + ", issuer=" + getIssuerDN());
            setSerialNumber(tmpcert.getSerialNumber().toString());

            // Default values for status and type
            setStatus(CertificateData.CERT_UNASSIGNED);
            setType(SecConst.USER_INVALID);
            setCAFingerprint(null);
            setExpireDate(tmpcert.getNotAfter());
            setRevocationDate(-1L);
            setRevocationReason(RevokedCertInfo.NOT_REVOKED);
        } catch (CertificateEncodingException cee) {
            log.error("Can't extract DER encoded certificate information.", cee);

            return null;
        }

        CertificateDataPK pk = new CertificateDataPK(getFingerprint());

        return pk;
    }

    /**
     * required method, does nothing
     *
     * @param incert certificate
     */
    public void ejbPostCreate(Certificate incert) {
        // Do nothing. Required.
    }
}
