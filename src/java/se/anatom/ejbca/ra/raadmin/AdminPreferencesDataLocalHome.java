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

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import se.anatom.ejbca.ra.raadmin.AdminPreference;


/**
 * For docs, see AdminPreferencesDataBean
 *
 * @version $Id: AdminPreferencesDataLocalHome.java,v 1.5 2004-04-16 07:38:41 anatom Exp $
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
