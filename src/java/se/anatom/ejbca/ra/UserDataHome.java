package se.anatom.ejbca.ra;

import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see UserDataBean
 *
 * @version $Id: UserDataHome.java,v 1.10 2003-07-24 08:43:31 anatom Exp $
 */
public interface UserDataHome extends javax.ejb.EJBHome {
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
     * @throws RemoteException DOCUMENT ME!
     */
    public UserDataRemote create(String username, String password, String dn)
        throws CreateException, NoSuchAlgorithmException, RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param pk DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public UserDataRemote findByPrimaryKey(UserDataPK pk)
        throws FinderException, RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public UserDataRemote findBySubjectDN(String dn) throws FinderException, RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param email DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public UserDataRemote findBySubjectEmail(String email)
        throws FinderException, RemoteException;

    /**
     * Finds users with a specified status.
     *
     * @param status the status of the required users
     *
     * @return Collection of UserDataRemote in no specific order
     */
    public Collection findByStatus(int status) throws FinderException, RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public Collection findAll() throws FinderException, RemoteException;
}
