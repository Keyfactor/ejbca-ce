package se.anatom.ejbca.ra;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;

/**
 * For docs, see UserDataBean
 *
 * @version $Id: UserDataLocalHome.java,v 1.4 2003-01-12 17:16:28 anatom Exp $
 **/
public interface UserDataLocalHome extends javax.ejb.EJBLocalHome {

    public UserDataLocal create(String username, String password, String dn)
        throws CreateException, NoSuchAlgorithmException;

    public UserDataLocal findByPrimaryKey(UserDataPK pk)
        throws FinderException;
    
    public UserDataLocal findBySubjectDN(String dn) 
        throws FinderException;
    
    public UserDataLocal findBySubjectEmail(String email) 
        throws FinderException;    


    /** Finds users with a specified status.
     * @param status the status of the required users
     * @return Collection of UserData in no specific order
     */

    public Collection findByStatus(int status)
        throws FinderException;

    public Collection findAll() 
        throws FinderException;      

}

