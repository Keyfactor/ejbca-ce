package se.anatom.ejbca.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see AdminEntityDataDataBean
 *
 * @version $Id: AdminEntityDataLocalHome.java,v 1.1 2003-09-04 14:26:37 herrvendil Exp $
 **/
public interface AdminEntityDataLocalHome extends javax.ejb.EJBLocalHome {

    public AdminEntityDataLocal create(String admingroupname, int caid, int matchwith, int matchtype, String matchvalue)
        throws CreateException;
    public AdminEntityDataLocal findByPrimaryKey(AdminEntityPK primarykey)
        throws FinderException;
}
