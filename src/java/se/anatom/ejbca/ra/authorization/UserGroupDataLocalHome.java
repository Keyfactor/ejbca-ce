package se.anatom.ejbca.ra.authorization;

import java.util.Collection;
import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see UserGroupDataBean
 *
 * @version $Id: UserGroupDataLocalHome.java,v 1.2 2002-07-23 16:02:58 anatom Exp $
 **/

public interface UserGroupDataLocalHome extends javax.ejb.EJBLocalHome {

    public UserGroupDataLocal create(String usergroupname)
        throws CreateException;

    public UserGroupDataLocal findByPrimaryKey(String usergroupname)
        throws FinderException;

    public Collection findAll()
        throws FinderException;

}

