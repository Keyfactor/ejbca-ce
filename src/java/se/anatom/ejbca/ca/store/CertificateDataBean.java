package se.anatom.ejbca.ca.store;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import java.math.BigInteger;
import java.security.cert.*;
import java.io.IOException;
import java.util.Date;

import org.apache.log4j.*;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Base64;

/**
 * Entity Bean representing a certificate.
 * Information stored:
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
 * </pre>
 **/
public abstract class CertificateDataBean implements javax.ejb.EntityBean {

    private static Category cat = Category.getInstance( CertificateDataBean.class.getName() );

    protected EntityContext  ctx;

    public abstract String getIssuerDN();
    /** Use setIssued instead
     * @see setIssuer
     */
    public abstract void setIssuerDN(String issuerDN);
    public abstract String getSubjectDN();
    /** Use setSubject instead
     * @see setSubject
     */
    public abstract void setSubjectDN(String subjectDN);
    public abstract String getFingerprint();
    public abstract void setFingerprint(String fingerprint);
    public abstract String getCAFingerprint();
    public abstract void setCAFingerprint(String cAFingerprint);
    public abstract int getStatus();
    public abstract void setStatus(int status);
    /** What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
     */
    public abstract int getType();
    /** What type of user the certificate belongs to, ex SecConst.USER_ENDUSER
     */
    public abstract void setType(int type);
    /** Serialnumber formated as BigInteger.toString() */
    public abstract String getSerialNumber();
    /** Serialnumber formated as BigInteger.toString() */
    public abstract void setSerialNumber(String serialNumber);
    /** Date formated as seconds since 1970 (== Date.getTime()) */
    public abstract long getExpireDate();
    /** Date formated as seconds since 1970 (== Date.getTime()) */
    public abstract void setExpireDate(long expireDate);
    /** Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime() */
    public abstract long getRevocationDate();
    /** Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime() */
    public abstract void setRevocationDate(long revocationDate);
    /** Set to revocation reason if status== CERT_REVOKED */
    public abstract int getRevocationReason();
    /** Set to revocation reason if status== CERT_REVOKED */
    public abstract void setRevocationReason(int revocationReason);
    public abstract String getBase64Cert();
    public abstract void setBase64Cert(String base64Cert);

    //
    // Public business methods used to help us manage certificates
    //
    public Certificate getCertificate() {
        X509Certificate cert = null;
        try {
            cert = CertTools.getCertfromByteArray(Base64.decode(getBase64Cert().getBytes()));
        } catch (IOException ioe) {
            cat.error("Can't decode certificate.", ioe);
            return null;
        } catch (CertificateException ce) {
            cat.error("Can't decode certificate.", ce);
            return null;
        }
        return cert;
    }
    public void setCertificate(Certificate incert) {
        try {
            String b64Cert = new String(Base64.encode(incert.getEncoded()));
            setBase64Cert(b64Cert);
            X509Certificate tmpcert = (X509Certificate)incert;
            String fp = CertTools.getFingerprintAsString(tmpcert);
            setFingerprint(fp);
            setSubjectDN(CertTools.stringToBCDNString(tmpcert.getSubjectDN().toString()));
            setIssuerDN(CertTools.stringToBCDNString(tmpcert.getIssuerDN().toString()));
            setSerialNumber(tmpcert.getSerialNumber().toString());
        } catch (CertificateEncodingException cee) {
            cat.error("Can't extract DER encoded certificate information.", cee);
        }
    }
    public void setIssuer(String dn) {
        setIssuerDN(CertTools.stringToBCDNString(dn));
    }
    public void setSubject(String dn) {
        setSubjectDN(CertTools.stringToBCDNString(dn));
    }
    public void setExpireDate(Date expireDate) {
        if (expireDate == null)
            setExpireDate(-1L);
        setExpireDate(expireDate.getTime());
    }
    public void setRevocationDate(Date revocationDate) {
        if (revocationDate == null)
            setRevocationDate(-1L);
        setRevocationDate(revocationDate.getTime());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a certficate.
     * Create by sending in the certificate, which extracts (from the cert)
     * fingerprint (primary key), subjectDN, issuerDN, serial number, expiration date.
     * Status, Type, CAFingerprint, revocationDate and revocationReason are set to default values
     * (CERT_UNASSIGNED, USER_INVALID, null, null and REASON_UNUSED)
     * and should be set using the respective set-methods.
     *
     * @param incert, the (X509)Certificate to be stored in the database.
     *
     **/
    public CertificateDataPK ejbCreate(Certificate incert) throws CreateException {
        // Exctract all fields to store with the certificate.
        X509Certificate tmpcert;
        try {
            String b64Cert = new String(Base64.encode(incert.getEncoded()));
            setBase64Cert(b64Cert);
            tmpcert = (X509Certificate)incert;
            String fp = CertTools.getFingerprintAsString(tmpcert);
            setFingerprint(fp);
        } catch (CertificateEncodingException cee) {
            cat.error("Can't extract DER encoded certificate information.", cee);
            return null;
        }
        // Make sure names are always looking the same
        setSubjectDN(CertTools.stringToBCDNString(tmpcert.getSubjectDN().toString()));
        setIssuerDN(CertTools.stringToBCDNString(tmpcert.getIssuerDN().toString()));
        cat.debug("Creating certdata, subject="+getSubjectDN()+", issuer="+getIssuerDN());
        setSerialNumber(tmpcert.getSerialNumber().toString());
        // Default values for status and type
        setStatus(CertificateData.CERT_UNASSIGNED);
        setType(SecConst.USER_INVALID);
        setCAFingerprint(null);
        setExpireDate(tmpcert.getNotAfter());
        setRevocationDate(-1L);
        setRevocationReason(CRLData.REASON_UNUSED);

        CertificateDataPK pk = new CertificateDataPK(getFingerprint());
        return pk;
    }
    public void ejbPostCreate(Certificate incert) {
        // Do nothing. Required.
    }
    public void setEntityContext(EntityContext ctx){
         this.ctx=ctx;
    }
    public void unsetEntityContext(){
         this.ctx=null;
    }
    public void ejbActivate(){
        // Not implemented.
    }
    public void ejbPassivate(){
        // Not implemented.
    }
    public void ejbLoad(){
        // Not implemented.
    }
    public void ejbStore(){
        // Not implemented.
    }
    public void ejbRemove(){
        // Not implemented.
    }
}
