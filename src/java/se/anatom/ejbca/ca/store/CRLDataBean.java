package se.anatom.ejbca.ca.store;

import javax.ejb.EntityContext;
import java.security.cert.*;
import java.io.IOException;
import java.util.Date;

import org.apache.log4j.*;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Base64;

/**
 * Entity Bean representing a CRL.
 * Information stored:
 * <pre>
 * CRL (b64crl)
 * Issuer DN (issuerDN)
 * CRLNumber (CRLNumber)
 * SHA1 fingerprint (fp)
 * CA SHA1 fingerprint (cafp)
 * thisUpdate (thisUpdate)
 * nextUpdate (nextUpdate)
 * </pre>
 **/
public class CRLDataBean implements javax.ejb.EntityBean {

    private static Category cat = Category.getInstance( CRLDataBean.class.getName() );

    public String b64crl;
    public String fp;
    public String issuerDN;
    public int CRLNumber;
    public String cafp;
    /** Date formated as seconds since 1970 (== Date.getTime()) */
    public long thisUpdate;
    /** Date formated as seconds since 1970 (== Date.getTime()) */
    public long nextUpdate;

    /**
     * Entity Bean holding info about a CRL.
     * Create by sending in the CRL, which extracts (from the crl)
     * fingerprint (primary key), CRLNumber, issuerDN, thisUpdate, nextUpdate.
     * CAFingerprint are set to default values (null)
     * and should be set using the respective set-methods.
     *
     * @param incrl, the (X509)CRL to be stored in the database.
     * @param number monotonically increasnig CRL number
     *
     **/
    public CRLDataPK ejbCreate(X509CRL incrl, int number) {
        // Exctract all fields to store with the certificate.
        try {
            b64crl = new String(Base64.encode(incrl.getEncoded()));
            fp = CertTools.getFingerprintAsString(incrl);
        } catch (CRLException ce) {
            cat.error("Can't extract DER encoded CRL.", ce);
            return null;
        }
        // Make sure names are always looking the same
        issuerDN = CertTools.stringToBCDNString(incrl.getIssuerDN().toString());
        cat.debug("Creating crldata, issuer="+issuerDN);
        // Default values for cafp
        cafp = null;
        CRLNumber = number;
        thisUpdate = incrl.getThisUpdate().getTime();
        nextUpdate = incrl.getNextUpdate().getTime();

        CRLDataPK pk = new CRLDataPK();
        pk.fp = fp;

        return pk;
    }
    public void ejbPostCreate(X509CRL incrl, int number) {
        // Do nothing. Required.
    }
    public X509CRL getCRL(){
        X509CRL crl = null;
        try {
            crl = CertTools.getCRLfromByteArray(Base64.decode(b64crl.getBytes()));
        } catch (IOException ioe) {
            cat.error("Can't decode CRL.", ioe);
            return null;
        } catch (CRLException ce) {
            cat.error("Can't decode CRL.", ce);
            return null;
        } catch (CertificateException ce) {
            cat.error("Can't generating CRL.", ce);
            return null;
        }
        return crl;
    }
    public void setCRL(X509CRL incrl){
        try {
            b64crl = new String(Base64.encode((incrl).getEncoded()));
        } catch (CRLException ce) {
            cat.error("Can't extract DER encoded CRL.", ce);
        }
    }
    public int getCRLNumber() {
        return CRLNumber;
    }
    public void setCRLNumber(int number) {
        CRLNumber = number;
    }
    public String getIssuer(){
        return issuerDN;
    }
    public void setIssuer(String dn) {
        issuerDN = CertTools.stringToBCDNString(dn);
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
    public Date getThisUpdate() {
        return new Date(thisUpdate);
    }
    public void setThisUpdate(Date date) {
        thisUpdate = date.getTime();
    }
    public Date getNextUpdate() {
        return new Date(nextUpdate);
    }
    public void setNextUpdate(Date date) {
        nextUpdate = date.getTime();
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
