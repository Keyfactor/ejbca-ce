package se.anatom.ejbca.authorization;

import java.util.Collection;
import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see AdminGroupDataBean
 *
 * @version $Id: AdminGroupDataLocalHome.java,v 1.2 2004-01-08 14:31:25 herrvendil Exp $
 **/

public interface AdminGroupDataLocalHome extends javax.ejb.EJBLocalHome {

    public AdminGroupDataLocal create(Integer pk, String admingroupname, int caid)
        throws CreateException;

    public AdminGroupDataLocal findByPrimaryKey(Integer pk)
        throws FinderException;
        
    public AdminGroupDataLocal findByGroupNameAndCAId(String groupname, int caid)        
	    throws FinderException;
	    
    public Collection findAll()
        throws FinderException;

}

