package se.anatom.ejbca.ra.raadmin;

import se.anatom.ejbca.ra.raadmin.AdminPreference;


/**
 * For docs, see AdminPreferencesDataBean
 *
 * @version $Id: AdminPreferencesDataLocal.java,v 1.3 2003-06-26 11:43:25 anatom Exp $
 */
public interface AdminPreferencesDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public String getId();

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     */
    public void setId(String id);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public AdminPreference getAdminPreference();

    /**
     * DOCUMENT ME!
     *
     * @param adminpreference DOCUMENT ME!
     */
    public void setAdminPreference(AdminPreference adminpreference);
}
