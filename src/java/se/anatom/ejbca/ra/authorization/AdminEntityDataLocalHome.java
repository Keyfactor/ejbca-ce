package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see AdminEntityDataDataBean
 *
 * @version $Id: AdminEntityDataLocalHome.java,v 1.2 2003-01-12 17:16:30 anatom Exp $
 **/
public interface AdminEntityDataLocalHome extends javax.ejb.EJBLocalHome {

    public AdminEntityDataLocal create(String admingroupname, int matchwith, int matchtype, String matchvalue)
        throws CreateException;
    public AdminEntityDataLocal findByPrimaryKey(AdminEntityPK primarykey)
        throws FinderException;
}
