package se.anatom.ejbca.ca.store;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
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
 * CRL (base64Crl)
 * IssuerDN (issuerDN)
 * CRLNumber (CRLNumber)
 * SHA1 fingerprint (fingerprint)
 * CA SHA1 fingerprint (cAFingerprint)
 * thisUpdate (thisUpdate)
 * nextUpdate (nextUpdate)
 * </pre>
 **/
public abstract class CRLDataBean implements javax.ejb.EntityBean {

    private static Category cat = Category.getInstance( CRLDataBean.class.getName() );

    protected EntityContext  ctx;

    public abstract int getCRLNumber();
    public abstract void setCRLNumber(int cRLNumber);
    public abstract String getIssuerDN();
    /** Use setIssued instead
     * @see setIssuer
     */
    public abstract void setIssuerDN(String issuerDN);
    public abstract String getFingerprint();
    public abstract void setFingerprint(String fingerprint);
    public abstract String getCAFingerprint();
    public abstract void setCAFingerprint(String cAFingerprint);
    public abstract long getThisUpdate();
    /** Date formated as seconds since 1970 (== Date.getTime()) */
    public abstract void setThisUpdate(long thisUpdate);
    public abstract long getNextUpdate();
    /** Date formated as seconds since 1970 (== Date.getTime()) */
    public abstract void setNextUpdate(long nextUpdate);
    public abstract String getBase64Crl();
    public abstract void setBase64Crl(String base64Crl);

    //
    // Public methods used to help us manage CRLs
    //

    public X509CRL getCRL() {
        X509CRL crl = null;
        try {
            String b64Crl = getBase64Crl();
            crl = CertTools.getCRLfromByteArray(Base64.decode(b64Crl.getBytes()));
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
            String b64Crl = new String(Base64.encode((incrl).getEncoded()));
            setBase64Crl(b64Crl);
        } catch (CRLException ce) {
            cat.error("Can't extract DER encoded CRL.", ce);
        }
    }
    public void setIssuer(String dn) {
        setIssuerDN(CertTools.stringToBCDNString(dn));
    }
    public void setThisUpdate(Date thisUpdate) {
        if (thisUpdate == null)
            setThisUpdate(-1L);
        setThisUpdate(thisUpdate.getTime());
    }
    public void setNextUpdate(Date nextUpdate) {
        if (nextUpdate == null)
            setNextUpdate(-1L);
        setNextUpdate(nextUpdate.getTime());
    }

    //
    // Fields required by Container
    //

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
    public CRLDataPK ejbCreate(X509CRL incrl, int number) throws CreateException {
        // Exctract all fields to store with the certificate.
        try {
            String b64Crl = new String(Base64.encode(incrl.getEncoded()));
            setBase64Crl(b64Crl);
            setFingerprint(CertTools.getFingerprintAsString(incrl));
        } catch (CRLException ce) {
            cat.error("Can't extract DER encoded CRL.", ce);
            return null;
        }
        // Make sure names are always looking the same
        setIssuerDN(CertTools.stringToBCDNString(incrl.getIssuerDN().toString()));
        cat.debug("Creating crldata, issuer="+getIssuerDN());
        // Default values for cafp
        setCAFingerprint(null);
        setCRLNumber(number);
        setThisUpdate(incrl.getThisUpdate());
        setNextUpdate(incrl.getNextUpdate());

        CRLDataPK pk = new CRLDataPK(getFingerprint());
        return pk;
    }
    public void ejbPostCreate(X509CRL incrl, int number) {
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
