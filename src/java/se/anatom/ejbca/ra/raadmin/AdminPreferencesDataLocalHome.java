package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import se.anatom.ejbca.ra.raadmin.AdminPreference;


/**
 * For docs, see AdminPreferencesDataBean
 *
 * @version $Id: AdminPreferencesDataLocalHome.java,v 1.4 2003-07-24 08:43:32 anatom Exp $
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
