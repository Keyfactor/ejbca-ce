package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;

/**
 * For docs, see AdminEntityDataDataBean
 *
 * @version $Id: AdminEntityDataLocalHome.java,v 1.1 2002-10-24 20:06:48 herrvendil Exp $
 **/

public interface AdminEntityDataLocalHome extends javax.ejb.EJBLocalHome {

    public AdminEntityDataLocal create(String admingroupname, int matchwith, int matchtype, String matchvalue)
        throws CreateException;


    public AdminEntityDataLocal findByPrimaryKey(AdminEntityPK primarykey)
        throws FinderException;


}

