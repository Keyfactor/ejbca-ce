package se.anatom.ejbca.ra;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

/**
 * For docs, see UserDataBean
 **/
public interface UserDataHome extends javax.ejb.EJBHome {

    public UserData create(String username, String password, String dn)
        throws CreateException, NoSuchAlgorithmException, RemoteException;

    public UserData findByPrimaryKey(UserDataPK pk)
        throws FinderException, RemoteException;

    public Collection findByStatus(int status)
        throws FinderException, RemoteException;
}
