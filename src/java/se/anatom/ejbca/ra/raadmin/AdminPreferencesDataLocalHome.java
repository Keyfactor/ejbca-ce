package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import se.anatom.ejbca.ra.raadmin.AdminPreference;

/**
 * For docs, see AdminPreferencesDataBean
 *
 * @version $Id: AdminPreferencesDataLocalHome.java,v 1.2 2003-01-12 17:16:33 anatom Exp $
 **/

public interface AdminPreferencesDataLocalHome extends javax.ejb.EJBLocalHome {

    public AdminPreferencesDataLocal create(String id, AdminPreference adminpreference)
        throws CreateException;



    public AdminPreferencesDataLocal findByPrimaryKey(String id)
        throws FinderException;

}

