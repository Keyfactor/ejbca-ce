package se.anatom.ejbca.hardtoken;

import se.anatom.ejbca.hardtoken.HardTokenIssuer;

import java.math.BigInteger;


/**
 * For docs, see HardTokenIssuerDataBean
 *
 * @version $Id: HardTokenIssuerDataLocal.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface HardTokenIssuerDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getAlias();

    /**
     * DOCUMENT ME!
     *
     * @param alias DOCUMENT ME!
     */
    public void setAlias(String alias);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public BigInteger getCertSN();

    /**
     * DOCUMENT ME!
     *
     * @param certificatesn DOCUMENT ME!
     */
    public void setCertSN(BigInteger certificatesn);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getCertIssuerDN();

    /**
     * DOCUMENT ME!
     *
     * @param certissuerdn DOCUMENT ME!
     */
    public void setCertIssuerDN(String certissuerdn);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public HardTokenIssuer getHardTokenIssuer();

    /**
     * DOCUMENT ME!
     *
     * @param issuerdata DOCUMENT ME!
     */
    public void setHardTokenIssuer(HardTokenIssuer issuerdata);
}
