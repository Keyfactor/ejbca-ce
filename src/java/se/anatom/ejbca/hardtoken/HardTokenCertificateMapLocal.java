package se.anatom.ejbca.hardtoken;

/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocal.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 */
public interface HardTokenCertificateMapLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public String getCertificateFingerprint();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getTokenSN();

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     */
    public void setTokenSN(String tokensn);
}
