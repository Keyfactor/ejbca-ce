package se.anatom.ejbca.ra.authorization;

import java.util.Collection;
import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see UserGroupDataBean
 **/

public interface UserGroupDataLocalHome extends javax.ejb.EJBLocalHome {

    public UserGroupDataLocal create(String usergroupname)
        throws CreateException;

    public UserGroupDataLocal findByPrimaryKey(String usergroupname)
        throws FinderException;
    
    public Collection findAll()
        throws FinderException;    

}

