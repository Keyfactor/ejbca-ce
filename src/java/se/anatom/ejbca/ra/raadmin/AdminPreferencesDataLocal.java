/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.ra.raadmin;

import se.anatom.ejbca.ra.raadmin.AdminPreference;


/**
 * For docs, see AdminPreferencesDataBean
 *
 * @version $Id: AdminPreferencesDataLocal.java,v 1.4 2004-04-16 07:38:41 anatom Exp $
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
