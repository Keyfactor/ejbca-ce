package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing
 * certificates placed on a token. Information stored:
 * <pre>
 *  certificatefingerprint
 *  tokensn
 * </pre>
 *
 * @version $Id: HardTokenCertificateMapBean.java,v 1.8 2003-07-24 08:43:30 anatom Exp $
 */
public abstract class HardTokenCertificateMapBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getCertificateFingerprint();

    /**
     * DOCUMENT ME!
     *
     * @param certificatefingerprint DOCUMENT ME!
     */
    public abstract void setCertificateFingerprint(String certificatefingerprint);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getTokenSN();

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     */
    public abstract void setTokenSN(String tokensn);

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of a certificate to hard token relation.
     *
     * @param certificatefingerprint DOCUMENT ME!
     * @param tokensn DOCUMENT ME!
     *
     * @return null
     */
    public String ejbCreate(String certificatefingerprint, String tokensn)
        throws CreateException {
        setCertificateFingerprint(certificatefingerprint);
        setTokenSN(tokensn);

        log.debug("Created HardTokenCertificateMap for token SN: " + tokensn);

        return certificatefingerprint;
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificatefingerprint DOCUMENT ME!
     * @param tokensn DOCUMENT ME!
     */
    public void ejbPostCreate(String certificatefingerprint, String tokensn) {
        // Do nothing. Required.
    }
}
