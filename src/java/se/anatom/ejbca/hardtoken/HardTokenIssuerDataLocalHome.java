package se.anatom.ejbca.hardtoken;

import java.math.BigInteger;
import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see HardTokenIssuerDataBean
 *
 * @version $Id: HardTokenIssuerDataLocalHome.java,v 1.4 2003-07-24 08:43:30 anatom Exp $
 */
public interface HardTokenIssuerDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param alias DOCUMENT ME!
     * @param certificatesn DOCUMENT ME!
     * @param certissuerdn DOCUMENT ME!
     * @param issuerdata DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public HardTokenIssuerDataLocal create(Integer id, String alias, BigInteger certificatesn,
        String certissuerdn, HardTokenIssuer issuerdata)
        throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public HardTokenIssuerDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @param alias DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public HardTokenIssuerDataLocal findByAlias(String alias)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @param certificatesn DOCUMENT ME!
     * @param certissuerdn DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public HardTokenIssuerDataLocal findByCertificateSN(String certificatesn, String certissuerdn)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public Collection findAll() throws FinderException;
}
