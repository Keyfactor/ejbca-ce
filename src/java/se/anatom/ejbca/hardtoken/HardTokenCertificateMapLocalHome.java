package se.anatom.ejbca.hardtoken;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see HardTokenCertificateMapBean
 *
 * @version $Id: HardTokenCertificateMapLocalHome.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 */
public interface HardTokenCertificateMapLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param certificatefingerprint DOCUMENT ME!
     * @param tokensn DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public HardTokenCertificateMapLocal create(String certificatefingerprint, String tokensn)
        throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param certificatefingerprint DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public HardTokenCertificateMapLocal findByPrimaryKey(String certificatefingerprint)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public Collection findByTokenSN(String tokensn) throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public Collection findAll() throws FinderException;
}
