package se.anatom.ejbca.ra.raadmin;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.math.BigInteger;
import se.anatom.ejbca.ra.raadmin.AdminPreference;

/**
 * For docs, see AdminPreferencesDataBean
 *
 * @version $Id: AdminPreferencesDataLocalHome.java,v 1.1 2002-10-24 20:09:29 herrvendil Exp $
 **/

public interface AdminPreferencesDataLocalHome extends javax.ejb.EJBLocalHome {

    public AdminPreferencesDataLocal create(String id, AdminPreference adminpreference)
        throws CreateException;



    public AdminPreferencesDataLocal findByPrimaryKey(String id)
        throws FinderException;

}

