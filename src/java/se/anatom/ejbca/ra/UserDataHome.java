package se.anatom.ejbca.ra;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;



/**
 * For docs, see UserDataBean
 *
 * @version $Id: UserDataHome.java,v 1.11 2003-09-04 14:36:14 herrvendil Exp $
 **/

public interface UserDataHome extends javax.ejb.EJBHome {

    public UserDataRemote create(String username, String password, String dn, int caid)
        throws CreateException, NoSuchAlgorithmException, RemoteException;


    public UserDataRemote findByPrimaryKey(UserDataPK pk)
        throws FinderException, RemoteException;

    public UserDataRemote findBySubjectDN(String dn, int caid)          
        throws FinderException, RemoteException;
    
     public Collection findBySubjectEmail(String email)          
        throws FinderException, RemoteException;   
    
    /** Finds users with a specified status.
     * @param status the status of the required users
     * @return Collection of UserDataRemote in no specific order
     */

    public Collection findByStatus(int status)
        throws FinderException, RemoteException;
    
    public Collection findAll() 
        throws FinderException, RemoteException;    
}

