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
 
package org.ejbca.core.ejb.ca.store;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;



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
 * Tag (tag)
 * Certificate Profile Id when issued (certificateProfileId)
 * Row update time (updateTime)
 * </pre>
 * 
 * KEEP THIS FILE IN SYNC WITH org.ejbca.core.ejb.ca.store.CertificateDataBean 
 *
 * @version $Id$
 *
 * @ejb.bean description="This enterprise bean entity represents a certificate with accompanying data"
 * display-name="CertificateDataEB"
 * name="CertificateData"
 * jndi-name="CertificateData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="CertificateDataBean"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.pk class="org.ejbca.core.ejb.ca.store.CertificateDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "CertificateData"
 * 
 * @ejb.home
 * generate="local"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.ejbca.core.ejb.ca.store.CertificateDataLocalHome"
 *
 * @ejb.interface
 * generate="local"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.ejbca.core.ejb.ca.store.CertificateDataLocal"
 *
 * @ejb.finder description="findByExpireDate"
 * signature="Collection findByExpireDate(long date)"
 * query="SELECT OBJECT(a) from CertificateDataBean a WHERE a.expireDate<?1"
 *
 * @ejb.finder description="findBySubjectDNAndIssuerDN"
 * signature="Collection findBySubjectDNAndIssuerDN(java.lang.String subjectDN, java.lang.String issuerDN)"
 * query="SELECT OBJECT(a) from CertificateDataBean a WHERE a.subjectDN=?1 AND a.issuerDN=?2"
  *
 * @ejb.finder description="findBySubjectDN"
 * signature="Collection findBySubjectDN(java.lang.String subjectDN)"
 * query="SELECT OBJECT(a) from CertificateDataBean a WHERE a.subjectDN=?1"
  *
 * @ejb.finder description="findBySerialNumber"
 * signature="Collection findBySerialNumber(java.lang.String sn)"
 * query="SELECT OBJECT(a) from CertificateDataBean a WHERE a.serialNumber=?1"
  *
 * @ejb.finder description="findByIssuerDNSerialNumber"
 * signature="Collection findByIssuerDNSerialNumber(java.lang.String issuerDN, java.lang.String serialNumber)"
 * query="SELECT OBJECT(a) from CertificateDataBean a WHERE a.issuerDN=?1 AND a.serialNumber=?2"
 *
 * The findByUsername orders first by expireDate and then by serialNumber. This is a special for CVC certificates who only have 
 * expire date granularity of one day, and serialNumber that is a sequence. So if several certificates are issued on the same day, 
 * the one with the highest serialNumber will be the latest.
 * 
 * @ejb.finder description="findByUsername"
 * signature="Collection findByUsername(java.lang.String username)"
 * query="SELECT OBJECT(a) from CertificateDataBean a WHERE  a.username=?1 ORDER BY a.expireDate DESC, a.serialNumber DESC"
 *
 * @ejb.finder description="findByUsernameAndStatus"
 * signature="Collection findByUsernameAndStatus(java.lang.String username, int status)"
 * query="SELECT OBJECT(a) from CertificateDataBean a WHERE a.username=?1 AND a.status=?2 ORDER BY a.expireDate DESC, a.serialNumber DESC"
 * 
 * @jboss.method-attributes
 *   pattern = "get*"
 *   read-only = "true"
 *
 * @jboss.method-attributes
 *   pattern = "find*"
 *   read-only = "true"
 *
 */
public abstract class CertificateDataBean extends BaseEntityBean {

    // Constants used to contruct KeyUsage
    /**
     * @see org.ejbca.core.ejb.ca.sign.ISignSessionRemote
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
     * @ejb.persistence column-name="issuerDN"
     * @ejb.interface-method
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
     * @ejb.persistence column-name="subjectDN"
     * @ejb.interface-method
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
     * @ejb.persistence column-name="fingerprint"
     * @ejb.interface-method
     * @ejb.pk-field 
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
     * @ejb.persistence column-name="cAFingerprint"
     * @ejb.interface-method
     */
    public abstract String getCaFingerprint();

    /**
     * Fingerprint of CA certificate
     *
     * @param cAFingerprint fingerprint
     * @ejb.interface-method
     */
    public abstract void setCaFingerprint(String caFingerprint);

    /**
     * status of certificate, ex SecConst.CERT_ACTIVE
     *
     * @return status
     * @ejb.persistence column-name="status"
     * @ejb.interface-method
     */
    public abstract int getStatus();

    /**
     * status of certificate, ex SecConst.CERT_ACTIVE
     *
     * @param status status
     * @ejb.interface-method
     */
    public abstract void setStatus(int status);

    /**
     * What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
     *
     * @return user type
     * @ejb.persistence column-name="type"
     * @ejb.interface-method
     */
    public abstract int getType();

    /**
     * What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
     *
     * @param type type
     * @ejb.interface-method
     */
    public abstract void setType(int type);

    /**
     * Serialnumber formated as BigInteger.toString()
     *
     * @return serial number
     * @ejb.persistence column-name="serialNumber"
     * @ejb.interface-method
     */
    public abstract String getSerialNumber();

    /**
     * Serialnumber formated as BigInteger.toString()
     *
     * @param serialNumber serial number
     * @ejb.interface-method
     */
    public abstract void setSerialNumber(String serialNumber);

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @return expire date
     * @ejb.persistence column-name="expireDate"
     * @ejb.interface-method
     */
    public abstract long getExpireDate();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     *
     * @param expireDate expire date
     * @ejb.interface-method
     */
    public abstract void setExpireDate(long expireDate);

    /**
     * Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime()
     *
     * @return revocation date
     * @ejb.persistence column-name="revocationDate"
     * @ejb.interface-method
     */
    public abstract long getRevocationDate();

    /**
     * Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime()
     *
     * @param revocationDate revocation date
     * @ejb.interface-method
     */
    public abstract void setRevocationDate(long revocationDate);

    /**
     * Set to revocation reason if status== CERT_REVOKED
     *
     * @return revocation reason
     * @ejb.persistence column-name="revocationReason"
     * @ejb.interface-method
     */
    public abstract int getRevocationReason();

    /**
     * Set to revocation reason if status== CERT_REVOKED
     *
     * @param revocationReason revocation reason
     * @ejb.interface-method
     */
    public abstract void setRevocationReason(int revocationReason);

    /**
     * certificate itself
     *
     * @return base64 encoded certificate
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="base64Cert"
     * @ejb.interface-method
     */
    public abstract String getBase64Cert();

    /**
     * certificate itself
     *
     * @param base64Cert base64 encoded certificate
     * @ejb.interface-method
     */
    public abstract void setBase64Cert(String base64Cert);

    /**
     * username in database
     *
     * @return username
     * @ejb.persistence column-name="username"
     * @ejb.interface-method
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @param username username
     *
     * @see org.ejbca.util.StringTools
     * @ejb.interface-method
     */
    public abstract void setUsername(String username);

    /**
     * tag in database. This field was added for the 3.9.0 release, but is not used yet.
     *
     * @return tag
     * @ejb.persistence column-name="tag"
     * @ejb.interface-method
     */
    public abstract String getTag();

    /**
     * tag in database. This field was added for the 3.9.0 release, but is not used yet.
     *
     * @param tag tag
     * @ejb.interface-method
     */
    public abstract void setTag(String tag);

    /**
     * Certificate Profile Id that was used to issue this certificate.
     *
     * @return certificateProfileId
     * @ejb.persistence column-name="certificateProfileId"
     * @ejb.interface-method
     */
    public abstract Integer getCertificateProfileId();

    /**
     * Certificate Profile Id that was used to issue this certificate.
     *
     * @param certificateProfileId certificateProfileId
     * @ejb.interface-method
     */
    public abstract void setCertificateProfileId(Integer certificateProfileId);

    /**
     * The time this row was last updated.
     *
     * @return updateTime
     * @ejb.persistence column-name="updateTime"
     * @ejb.interface-method
     */
    public abstract long getUpdateTime();

    /**
     * The time this row was last updated.
     *
     * @param updateTime updateTime
     * @ejb.interface-method
     */
    public abstract void setUpdateTime(long updateTime);

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
        Certificate cert = null;
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

            String fp = CertTools.getFingerprintAsString(incert);
            setFingerprint(fp);
            setSubjectDN(CertTools.getSubjectDN(incert));
            setIssuerDN(CertTools.getIssuerDN(incert));
            setSerialNumber(CertTools.getSerialNumber(incert).toString());
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
        try {
            String b64Cert = new String(Base64.encode(incert.getEncoded()));
            setBase64Cert(b64Cert);

            String fp = CertTools.getFingerprintAsString(incert);
            setFingerprint(fp);

            // Make sure names are always looking the same
            setSubjectDN(CertTools.getSubjectDN(incert));
            setIssuerDN(CertTools.getIssuerDN(incert));
            if (log.isDebugEnabled()) {
                log.debug("Creating certdata, subject=" + getSubjectDN() + ", issuer=" + getIssuerDN()+", fingerprint="+fp);            	
            }
            setSerialNumber(CertTools.getSerialNumber(incert).toString());

            // Default values for status and type
            setStatus(SecConst.CERT_UNASSIGNED);
            setType(SecConst.USER_INVALID);
            setCaFingerprint(null);
            setExpireDate(CertTools.getNotAfter(incert));
            setRevocationDate(-1L);
            setRevocationReason(RevokedCertInfo.NOT_REVOKED);
            setUpdateTime(0);
            setCertificateProfileId(0);
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
