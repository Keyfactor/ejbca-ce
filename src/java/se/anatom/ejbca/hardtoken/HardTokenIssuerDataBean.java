package se.anatom.ejbca.hardtoken;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;

import java.math.BigInteger;

import java.util.HashMap;

import javax.ejb.CreateException;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * hard token issuer in the ra. Information stored:
 * <pre>
 *  id (Primary key)
 *  alias (of the hard token issuer)
 *  certificatesn (Certificate SN of the hard token issuer)
 *  certificateissuersn (The SN of the certificate issuing the hard toke issuers certificate.)
 *  hardtokenissuer (Data saved concerning the hard token issuer)
 * </pre>
 *
 * @version $Id: HardTokenIssuerDataBean.java,v 1.5 2003-06-26 11:43:24 anatom Exp $
 */
public abstract class HardTokenIssuerDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     */
    public abstract void setId(Integer id);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getAlias();

    /**
     * DOCUMENT ME!
     *
     * @param alias DOCUMENT ME!
     */
    public abstract void setAlias(String alias);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getCertificateSN();

    /**
     * DOCUMENT ME!
     *
     * @param certificatesn DOCUMENT ME!
     */
    public abstract void setCertificateSN(String certificatesn);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getCertIssuerDN();

    /**
     * DOCUMENT ME!
     *
     * @param certissuerdn DOCUMENT ME!
     */
    public abstract void setCertIssuerDN(String certissuerdn);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract HashMap getData();

    /**
     * DOCUMENT ME!
     *
     * @param data DOCUMENT ME!
     */
    public abstract void setData(HashMap data);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public BigInteger getCertSN() {
        return new BigInteger(getCertificateSN(), 16);
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificatesn DOCUMENT ME!
     */
    public void setCertSN(BigInteger certificatesn) {
        setCertificateSN(certificatesn.toString(16));
    }

    /**
     * Method that returns the hard token issuer data and updates it if nessesary.
     *
     * @return DOCUMENT ME!
     */
    public HardTokenIssuer getHardTokenIssuer() {
        HardTokenIssuer returnval = new HardTokenIssuer();
        returnval.loadData((Object) getData());

        return returnval;
    }

    /**
     * Method that saves the hard token issuer data to database.
     *
     * @param hardtokenissuer DOCUMENT ME!
     */
    public void setHardTokenIssuer(HardTokenIssuer hardtokenissuer) {
        setData((HashMap) hardtokenissuer.saveData());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of a ahrd token issuer.
     *
     * @param id DOCUMENT ME!
     * @param alias DOCUMENT ME!
     * @param certificatesn DOCUMENT ME!
     * @param certissuerdn DOCUMENT ME!
     * @param issuerdata DOCUMENT ME!
     *
     * @return null
     */
    public Integer ejbCreate(Integer id, String alias, BigInteger certificatesn,
        String certissuerdn, HardTokenIssuer issuerdata)
        throws CreateException {
        setId(id);
        setAlias(alias);
        setCertificateSN(certificatesn.toString(16));
        setCertIssuerDN(certissuerdn);
        setHardTokenIssuer(issuerdata);

        log.debug("Created Hard Token Issuer " + alias);

        return id;
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param alias DOCUMENT ME!
     * @param certificatesn DOCUMENT ME!
     * @param certissuerdn DOCUMENT ME!
     * @param issuerdata DOCUMENT ME!
     */
    public void ejbPostCreate(Integer id, String alias, BigInteger certificatesn,
        String certissuerdn, HardTokenIssuer issuerdata) {
        // Do nothing. Required.
    }
}
