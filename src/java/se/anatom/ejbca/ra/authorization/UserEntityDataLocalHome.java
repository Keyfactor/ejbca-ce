package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;

/**

 * For docs, see UserEnityDataDataBean

 **/

public interface UserEntityDataLocalHome extends javax.ejb.EJBLocalHome {

    public UserEntityDataLocal create(String usergroupname, int matchwith, int matchtype, String matchvalue)
        throws CreateException;


    public UserEntityDataLocal findByPrimaryKey(UserEntityPK primarykey)
        throws FinderException;
    

}

