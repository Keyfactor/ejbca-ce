package se.anatom.ejbca.ca.store;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;

import java.io.IOException;

import java.security.cert.*;

import java.util.Date;

import javax.ejb.CreateException;


/**
 * Entity Bean representing a CRL. Information stored:
 * <pre>
 * CRL (base64Crl)
 * IssuerDN (issuerDN)
 * CRLNumber (CRLNumber)
 * SHA1 fingerprint (fingerprint)
 * CA SHA1 fingerprint (cAFingerprint)
 * thisUpdate (thisUpdate)
 * nextUpdate (nextUpdate)
 * </pre>
 *
 * @version $Id: CRLDataBean.java,v 1.12 2003-06-26 11:43:23 anatom Exp $
 */
public abstract class CRLDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(CRLDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract int getCRLNumber();

    /**
     * DOCUMENT ME!
     *
     * @param cRLNumber DOCUMENT ME!
     */
    public abstract void setCRLNumber(int cRLNumber);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getIssuerDN();

    /**
     * Use setIssuer instead
     *
     * @see #setIssuer(String)
     */
    public abstract void setIssuerDN(String issuerDN);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getFingerprint();

    /**
     * DOCUMENT ME!
     *
     * @param fingerprint DOCUMENT ME!
     */
    public abstract void setFingerprint(String fingerprint);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getCAFingerprint();

    /**
     * DOCUMENT ME!
     *
     * @param cAFingerprint DOCUMENT ME!
     */
    public abstract void setCAFingerprint(String cAFingerprint);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract long getThisUpdate();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     */
    public abstract void setThisUpdate(long thisUpdate);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract long getNextUpdate();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     */
    public abstract void setNextUpdate(long nextUpdate);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getBase64Crl();

    /**
     * DOCUMENT ME!
     *
     * @param base64Crl DOCUMENT ME!
     */
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
            log.error("Can't decode CRL.", ioe);

            return null;
        } catch (CRLException ce) {
            log.error("Can't decode CRL.", ce);

            return null;
        } catch (CertificateException ce) {
            log.error("Can't generating CRL.", ce);

            return null;
        }

        return crl;
    }

    /**
     * DOCUMENT ME!
     *
     * @param incrl DOCUMENT ME!
     */
    public void setCRL(X509CRL incrl) {
        try {
            String b64Crl = new String(Base64.encode((incrl).getEncoded()));
            setBase64Crl(b64Crl);
        } catch (CRLException ce) {
            log.error("Can't extract DER encoded CRL.", ce);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     */
    public void setIssuer(String dn) {
        setIssuerDN(CertTools.stringToBCDNString(dn));
    }

    /**
     * DOCUMENT ME!
     *
     * @param thisUpdate DOCUMENT ME!
     */
    public void setThisUpdate(Date thisUpdate) {
        if (thisUpdate == null) {
            setThisUpdate(-1L);
        }

        setThisUpdate(thisUpdate.getTime());
    }

    /**
     * DOCUMENT ME!
     *
     * @param nextUpdate DOCUMENT ME!
     */
    public void setNextUpdate(Date nextUpdate) {
        if (nextUpdate == null) {
            setNextUpdate(-1L);
        }

        setNextUpdate(nextUpdate.getTime());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a CRL. Create by sending in the CRL, which extracts (from the
     * crl) fingerprint (primary key), CRLNumber, issuerDN, thisUpdate, nextUpdate. CAFingerprint
     * are set to default values (null) and should be set using the respective set-methods.
     *
     * @param incrl the (X509)CRL to be stored in the database.
     * @param number monotonically increasnig CRL number
     *
     * @return DOCUMENT ME!
     */
    public CRLDataPK ejbCreate(X509CRL incrl, int number)
        throws CreateException {
        // Exctract all fields to store with the certificate.
        try {
            String b64Crl = new String(Base64.encode(incrl.getEncoded()));
            setBase64Crl(b64Crl);
            setFingerprint(CertTools.getFingerprintAsString(incrl));

            // Make sure names are always looking the same
            setIssuerDN(CertTools.getIssuerDN(incrl));
            log.debug("Creating crldata, issuer=" + getIssuerDN());

            // Default values for cafp
            setCAFingerprint(null);
            setCRLNumber(number);
            setThisUpdate(incrl.getThisUpdate());
            setNextUpdate(incrl.getNextUpdate());
        } catch (CRLException ce) {
            log.error("Can't extract DER encoded CRL.", ce);

            return null;
        }

        CRLDataPK pk = new CRLDataPK(getFingerprint());

        return pk;
    }

    /**
     * DOCUMENT ME!
     *
     * @param incrl DOCUMENT ME!
     * @param number DOCUMENT ME!
     */
    public void ejbPostCreate(X509CRL incrl, int number) {
        // Do nothing. Required.
    }
}
