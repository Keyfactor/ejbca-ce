package se.anatom.ejbca.hardtoken;

import java.util.Collection;
import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;


/**
 * For docs, see HardTokenDataBean
 *
 * @version $Id: HardTokenDataLocalHome.java,v 1.3 2003-07-24 08:43:30 anatom Exp $
 */
public interface HardTokenDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param createtime DOCUMENT ME!
     * @param modifytime DOCUMENT ME!
     * @param tokentype DOCUMENT ME!
     * @param tokendata DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public HardTokenDataLocal create(String tokensn, String username, Date createtime,
        Date modifytime, int tokentype, HardToken tokendata)
        throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param tokensn DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public HardTokenDataLocal findByPrimaryKey(String tokensn)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public Collection findByUsername(String username) throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public Collection findAll() throws FinderException;
}
