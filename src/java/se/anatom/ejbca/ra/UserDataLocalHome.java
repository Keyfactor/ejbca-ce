package se.anatom.ejbca.ra;

import java.security.NoSuchAlgorithmException;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see UserDataBean
 *
 * @version $Id: UserDataLocalHome.java,v 1.5 2003-06-26 11:43:24 anatom Exp $
 */
public interface UserDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param username DOCUMENT ME!
     * @param password DOCUMENT ME!
     * @param dn DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     */
    public UserDataLocal create(String username, String password, String dn)
        throws CreateException, NoSuchAlgorithmException;

    /**
     * DOCUMENT ME!
     *
     * @param pk DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public UserDataLocal findByPrimaryKey(UserDataPK pk)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public UserDataLocal findBySubjectDN(String dn) throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @param email DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public UserDataLocal findBySubjectEmail(String email)
        throws FinderException;

    /**
     * Finds users with a specified status.
     *
     * @param status the status of the required users
     *
     * @return Collection of UserData in no specific order
     */
    public Collection findByStatus(int status) throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public Collection findAll() throws FinderException;
}
