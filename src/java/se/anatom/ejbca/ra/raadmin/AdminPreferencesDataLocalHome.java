package se.anatom.ejbca.ra.raadmin;

import se.anatom.ejbca.ra.raadmin.AdminPreference;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see AdminPreferencesDataBean
 *
 * @version $Id: AdminPreferencesDataLocalHome.java,v 1.3 2003-06-26 11:43:25 anatom Exp $
 */
public interface AdminPreferencesDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public AdminPreferencesDataLocal create(String id, AdminPreference adminpreference)
        throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public AdminPreferencesDataLocal findByPrimaryKey(String id)
        throws FinderException;
}
