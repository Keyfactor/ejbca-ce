package se.anatom.ejbca.ca.store;

import javax.ejb.EntityContext;
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
 * Certificate (b64Cert)
 * Subject DN (subjectDN)
 * Issuer DN (issuerDN)
 * Serial number (serno)
 * SHA1 fingerprint (fp)
 * Status (status)
 * Type (type, from UserData)
 * CA SHA1 fingerprint (cafp)
 * Expiration date (expireDate)
 * Revocation date (revocationDate)
 * Revocation reason (revocationReason)
 * </pre>
 **/
public class CertificateDataBean implements javax.ejb.EntityBean {

    private static Category cat = Category.getInstance( CertificateDataBean.class.getName() );

    public String b64Cert;
    public String fp;
    public String subjectDN;
    public String issuerDN;
    public String serno;
    public int status;
    public int type;
    public String cafp;
    /** Date formated as seconds since 1970 (== Date.getTime()) */
    public long expireDate;
    /** Set to date when revocation occured if status== CERT_REVOKED. Format == Date.getTime() */
    public long revocationDate;
    /** Set to revocation reason if status== CERT_REVOKED */
    public int revocationReason;

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
    public CertificateDataPK ejbCreate(Certificate incert) {
        // Exctract all fields to store with the certificate.
        X509Certificate tmpcert;
        try {
            b64Cert = new String(Base64.encode(incert.getEncoded()));
            tmpcert = (X509Certificate)incert;
            fp = CertTools.getFingerprintAsString(tmpcert);
        } catch (CertificateEncodingException cee) {
            cat.error("Can't extract DER encoded certificate information.", cee);
            return null;
        }
        // Make sure names are always looking the same
        subjectDN = CertTools.stringToBCDNString(tmpcert.getSubjectDN().toString());
        issuerDN = CertTools.stringToBCDNString(tmpcert.getIssuerDN().toString());
        cat.debug("Creating certdata, subject="+subjectDN+", issuer="+issuerDN);
        serno = tmpcert.getSerialNumber().toString();
        // Default values for status and type
        status = CertificateData.CERT_UNASSIGNED;
        type = SecConst.USER_INVALID;
        cafp = null;
        expireDate = tmpcert.getNotAfter().getTime();
        revocationDate = -1;
        revocationReason = CRLData.REASON_UNUSED;

        CertificateDataPK pk = new CertificateDataPK();
        pk.fp = fp;

        return pk;
    }
    public void ejbPostCreate(Certificate incert) {
        // Do nothing. Required.
    }
    public String getB64Cert() {
        return b64Cert;
    }
    public Certificate getCertificate() {
        X509Certificate cert = null;
        try {
            cert = CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes()));
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
            b64Cert = new String(Base64.encode(incert.getEncoded()));
        } catch (CertificateEncodingException cee) {
            cat.error("Can't extract DER encoded certificate information.", cee);
        }
    }
    public String getIssuer() {
        return issuerDN;
    }
    public void setIssuer(String dn) {
        issuerDN = CertTools.stringToBCDNString(dn);
    }
    public String getSubject(){
        return subjectDN;
    }
    public void setSubject(String dn) {
        subjectDN = CertTools.stringToBCDNString(dn);
    }
    public String getFingerprint(){
        return fp;
    }
    public void setFingerprint(String f) {
        fp = f;
    }
    public String getCAFingerprint(){
        return cafp;
    }
    public void setCAFingerprint(String f) {
        cafp = f;
    }
    public int getStatus(){
        return status;
    }
    public void setStatus(int st) {
        status = st;
    }
    public int getType(){
        return type;
    }
    public void setType(int t){
        type = t;
    }
    public BigInteger getSerialNumber(){
        return new BigInteger(serno);
    }
    public void setSerialNumber(BigInteger s){
        serno = s.toString();
    }
    public Date getExpireDate() {
        return new Date(expireDate);
    }
    public void setExpireDate(Date date) {
        expireDate = date.getTime();
    }
    public Date getRevocationDate() {
        return new Date(revocationDate);
    }
    public void setRevocationDate(Date date) {
        revocationDate = date.getTime();
    }
    public int getRevocationReason() {
        return revocationReason;
    }
    public void setRevocationReason(int reason  ) {
        revocationReason = reason;
    }

    public void setEntityContext(EntityContext ctx){
         // Not implemented.
    }
    public void unsetEntityContext(){
         // Not implemented.
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
