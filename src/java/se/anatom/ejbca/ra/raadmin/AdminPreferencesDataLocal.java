package se.anatom.ejbca.ra.raadmin;

import se.anatom.ejbca.ra.raadmin.AdminPreference;

/**
 * For docs, see AdminPreferencesDataBean
 *
 * @version $Id: AdminPreferencesDataLocal.java,v 1.2 2003-01-12 17:16:33 anatom Exp $
 **/

public interface AdminPreferencesDataLocal extends javax.ejb.EJBLocalObject {

    // public methods

    public String getId();

    public void setId(String id);

    public AdminPreference getAdminPreference();

    public void setAdminPreference(AdminPreference adminpreference);

}

