package se.anatom.ejbca.ca.store;

import java.security.cert.X509CRL;
import java.util.Date;


/**
 * For docs, see CRLDataBean
 */
public interface CRLDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public int getCRLNumber();

    /**
     * DOCUMENT ME!
     *
     * @param cRLNumber DOCUMENT ME!
     */
    public void setCRLNumber(int cRLNumber);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getIssuerDN();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getFingerprint();

    /**
     * DOCUMENT ME!
     *
     * @param fingerprint DOCUMENT ME!
     */
    public void setFingerprint(String fingerprint);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getCAFingerprint();

    /**
     * DOCUMENT ME!
     *
     * @param cAFingerprint DOCUMENT ME!
     */
    public void setCAFingerprint(String cAFingerprint);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public long getThisUpdate();

    /**
     * DOCUMENT ME!
     *
     * @param thisUpdate DOCUMENT ME!
     */
    public void setThisUpdate(long thisUpdate);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public long getNextUpdate();

    /**
     * DOCUMENT ME!
     *
     * @param nextUpdate DOCUMENT ME!
     */
    public void setNextUpdate(long nextUpdate);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getBase64Crl();

    /**
     * DOCUMENT ME!
     *
     * @param base64Crl DOCUMENT ME!
     */
    public void setBase64Crl(String base64Crl);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public X509CRL getCRL();

    /**
     * DOCUMENT ME!
     *
     * @param crl DOCUMENT ME!
     */
    public void setCRL(X509CRL crl);

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     */
    public void setIssuer(String dn);

    /**
     * DOCUMENT ME!
     *
     * @param thisUpdate DOCUMENT ME!
     */
    public void setThisUpdate(Date thisUpdate);

    /**
     * DOCUMENT ME!
     *
     * @param nextUpdate DOCUMENT ME!
     */
    public void setNextUpdate(Date nextUpdate);
}
