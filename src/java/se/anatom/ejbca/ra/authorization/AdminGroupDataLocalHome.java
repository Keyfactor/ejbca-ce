package se.anatom.ejbca.ra.authorization;

import java.util.Collection;
import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see AdminGroupDataBean
 *
 * @version $Id: AdminGroupDataLocalHome.java,v 1.1 2002-10-24 20:07:17 herrvendil Exp $
 **/

public interface AdminGroupDataLocalHome extends javax.ejb.EJBLocalHome {

    public AdminGroupDataLocal create(String admingroupname)
        throws CreateException;

    public AdminGroupDataLocal findByPrimaryKey(String admingroupname)
        throws FinderException;

    public Collection findAll()
        throws FinderException;

}

