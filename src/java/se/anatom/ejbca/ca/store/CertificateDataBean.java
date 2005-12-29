/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.ca.store;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
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
 * Type (type; endentity, ca etc)
 * CA SHA1 fingerprint (cAFingerprint)
 * Expiration date (expireDate)
 * Revocation date (revocationDate)
 * Revocation reason (revocationReason)
 * Username (username)
 * </pre>
 *
 * @version $Id: CertificateDataBean.java,v 1.36 2005-12-29 13:51:29 anatom Exp $
 *
 * @ejb.bean description="This enterprise bean entity represents a certificate with accompanying data"
 * display-name="CertificateDataEB"
 * name="CertificateData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="CertificateDataBean"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.pk class="se.anatom.ejbca.ca.store.CertificateDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "CertificateData"
 * 
 * @ejb.home
 * generate="local"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="se.anatom.ejbca.ca.store.CertificateDataLocalHome"
 *
 * @ejb.interface
 * generate="local"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="se.anatom.ejbca.ca.store.CertificateDataLocal"
 *
 * @ejb.finder description="findByExpireDate"
 * signature="Collection findByExpireDate(long date)"
 * query="SELECT DISTINCT OBJECT(a) from CertificateDataBean a WHERE a.expireDate<?1"
 *
 * @ejb.finder description="findBySubjectDNAndIssuerDN"
 * signature="Collection findBySubjectDNAndIssuerDN(java.lang.String subjectDN, java.lang.String issuerDN)"
 * query="SELECT DISTINCT OBJECT(a) from CertificateDataBean a WHERE a.subjectDN=?1 AND a.issuerDN=?2"
  *
 * @ejb.finder description="findBySubjectDN"
 * signature="Collection findBySubjectDN(java.lang.String subjectDN)"
 * query="SELECT DISTINCT OBJECT(a) from CertificateDataBean a WHERE a.subjectDN=?1"
  *
 * @ejb.finder description="findBySerialNumber"
 * signature="Collection findBySerialNumber(java.lang.String sn)"
 * query="SELECT DISTINCT OBJECT(a) from CertificateDataBean a WHERE a.serialNumber=?1"
  *
 * @ejb.finder description="findByIssuerDNSerialNumber"
 * signature="Collection findByIssuerDNSerialNumber(java.lang.String issuerDN, java.lang.String serialNumber)"
 * query="SELECT DISTINCT OBJECT(a) from CertificateDataBean a WHERE a.issuerDN=?1 AND a.serialNumber=?2"
 *
 * @ejb.finder description="findByUsername"
 * signature="Collection findByUsername(java.lang.String username)"
 * query="SELECT DISTINCT OBJECT(a) from CertificateDataBean a WHERE  a.username=?1"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class CertificateDataBean extends BaseEntityBean {

    /** Certificate doesn't belong to anyone */
    public static final int CERT_UNASSIGNED = 0;

    /** Assigned, but not yet active */
    public static final int CERT_INACTIVE = 10;

    /** Certificate is active and assigned */
    public static final int CERT_ACTIVE = 20;

    /** Certificate is temporarily blocked (reversible) */
    public static final int CERT_TEMP_REVOKED = 30;

    /** Certificate is permanently blocked (terminated) */
    public static final int CERT_REVOKED = 40;

    /** Certificate is expired */
    public static final int CERT_EXPIRED = 50;

    /** Certificate is expired and kept for archive purpose */
    public static final int CERT_ARCHIVED = 60;

    // Certificate types used to create certificates
    /** Certificate used for encryption. */
    public static final int CERT_TYPE_ENCRYPTION = 0x1;

    /** Certificate used for digital signatures. */
    public static final int CERT_TYPE_SIGNATURE = 0x2;

    /** Certificate used for both encryption and signatures. */
    public static final int CERT_TYPE_ENCSIGN = 0x3;

    // Constants used in certificate generation and publication. */
    /** Certificate belongs to an end entity. */
    public static final int CERTTYPE_ENDENTITY  =     0x1;    
    /** Certificate belongs to a sub ca. */
    public static final int CERTTYPE_SUBCA      =     0x2;
    /** Certificate belongs to a root ca. */
    public static final int CERTTYPE_ROOTCA     =     0x8;        
    /** Certificate belongs on a hard token. */
    public static final int CERTTYPE_HARDTOKEN  =     0x16;

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

    private static final Logger log = Logger.getLogger(CertificateDataBean.class);

    /**
     * DN of issuer of certificate
     *
     * @return issuer dn
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getIssuerDN();

    /**
     * Use setIssuer instead
     *
     * @param issuerDN issuer dn
     *
     * @see #setIssuer(String)
     * @ejb.persistence
     */
    public abstract void setIssuerDN(String issuerDN);

    /**
     * DN of subject in certificate
     *
     * @return subject dn
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getSubjectDN();

    /**
     * Use setSubject instead
     *
     * @param subjectDN subject dn
     *
     * @see #setSubject(String)
     * @ejb.persistence
     */
    public abstract void setSubjectDN(String subjectDN);

    /**
     * Fingerprint of certificate
     *
     * @return fingerprint
     * @ejb.persistence
     * @ejb.interface-method
     * @ejb.pk-field 
     */
    public abstract String getFingerprint();

    /**
     * Fingerprint of certificate
     *
     * @param fingerprint fingerprint
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setFingerprint(String fingerprint);

    /**
     * Fingerprint of CA certificate
     *
     * @return fingerprint
     * @ejb.persistence column-name="cAFingerprint"
     * @ejb.interface-method
     */
    public abstract String getCaFingerprint();

    /**
     * Fingerprint of CA certificate
     *
     * @param cAFingerprint fingerprint
     * @ejb.persistence column-name="cAFingerprint"
     * @ejb.interface-method
     */
    public abstract void setCaFingerprint(String caFingerprint);

    /**
     * status of certificate, ex CertificateData.CERT_ACTIVE
     *
     * @return status
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getStatus();

    /**
     * status of certificate, ex CertificateData.CERT_ACTIVE
     *
     * @param status status
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setStatus(int status);

    /**
     * What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
     *
     * @return user type
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getType();

    /**
     * What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
     *
     * @param type type
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setType(int type);

    /**
     * Serialnumber formated as BigInteger.toString()
     *
     * @return serial number
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getSerialNumber();

    /**
     * Serialnumber formated as BigInteger.toString()
     *
     * @param serialNumber serial number
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setSerialNumber(String serialNumber);

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @return expire date
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract long getExpireDate();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @param expireDate expire date
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setExpireDate(long expireDate);

    /**
     * Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime()
     *
     * @return revocation date
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract long getRevocationDate();

    /**
     * Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime()
     *
     * @param revocationDate revocation date
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setRevocationDate(long revocationDate);

    /**
     * Set to revocation reason if status== CERT_REVOKED
     *
     * @return revocation reason
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getRevocationReason();

    /**
     * Set to revocation reason if status== CERT_REVOKED
     *
     * @param revocationReason revocation reason
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setRevocationReason(int revocationReason);

    /**
     * certificate itself
     *
     * @return base64 encoded certificate
     * @ejb.persistence jdbc-type="LONGVARCHAR"
     * @ejb.interface-method
     */
    public abstract String getBase64Cert();

    /**
     * certificate itself
     *
     * @param base64Cert base64 encoded certificate
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setBase64Cert(String base64Cert);

    /**
     * username in database
     *
     * @return username
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @param username username
     *
     * @see se.anatom.ejbca.util.StringTools
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setUsername(String username);

    //
    // Public business methods used to help us manage certificates
    //

    /**
     * certificate itself
     *
     * @return certificate
     * @ejb.interface-method
     */
    public Certificate getCertificate() {
        X509Certificate cert = null;
        try {
            cert = CertTools.getCertfromByteArray(Base64.decode(getBase64Cert().getBytes()));
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
     * @ejb.interface-method
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
     * @ejb.interface-method
     */
    public void setIssuer(String dn) {
        setIssuerDN(CertTools.stringToBCDNString(dn));
    }

    /**
     * DN of subject in certificate
     *
     * @param dn subject dn
     * @ejb.interface-method
     */
    public void setSubject(String dn) {
        setSubjectDN(CertTools.stringToBCDNString(dn));
    }

    /**
     * expire date of certificate
     *
     * @param expireDate expire date
     * @ejb.interface-method
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
     * @ejb.interface-method
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
     * @ejb.create-method
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
            setStatus(CERT_UNASSIGNED);
            setType(SecConst.USER_INVALID);
            setCaFingerprint(null);
            setExpireDate(tmpcert.getNotAfter());
            setRevocationDate(-1L);
            setRevocationReason(RevokedCertInfo.NOT_REVOKED);
        } catch (CertificateEncodingException cee) {
            log.error("Can't extract DER encoded certificate information.", cee);
            // TODO should throw an exception
        }
        return null;
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
