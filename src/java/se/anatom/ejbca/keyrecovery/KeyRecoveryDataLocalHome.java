package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;

import java.security.KeyPair;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocalHome.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface KeyRecoveryDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param certificatesn DOCUMENT ME!
     * @param issuerdn DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param keypair DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public KeyRecoveryDataLocal create(BigInteger certificatesn, String issuerdn, String username,
        KeyPair keypair) throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param pk DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public KeyRecoveryDataLocal findByPrimaryKey(KeyRecoveryDataPK pk)
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
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public Collection findByUserMark(String username) throws FinderException;
}
