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

import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing
 * admin preference. Information stored:
 * <pre>
 * Id  (BigInteger SerialNumber)
 * AdminPreference
 * </pre>
 *
 * @version $Id: AdminPreferencesDataBean.java,v 1.8 2004-04-16 07:38:41 anatom Exp $
 */
public abstract class AdminPreferencesDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(AdminPreferencesDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getId();

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     */
    public abstract void setId(String id);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract HashMap getData();

    /**
     * DOCUMENT ME!
     *
     * @param data DOCUMENT ME!
     */
    public abstract void setData(HashMap data);

    /**
     * Method that returns the admin preference and updates it if nessesary.
     *
     * @return DOCUMENT ME!
     */
    public AdminPreference getAdminPreference() {
        AdminPreference returnval = new AdminPreference();
        returnval.loadData((Object) getData());

        return returnval;
    }

    /**
     * Method that saves the admin preference to database.
     *
     * @param adminpreference DOCUMENT ME!
     */
    public void setAdminPreference(AdminPreference adminpreference) {
        setData((HashMap) adminpreference.saveData());
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of admin preferences.
     *
     * @param id the serialnumber.
     * @param adminpreference is the AdminPreference.
     *
     * @return the primary key
     */
    public String ejbCreate(String id, AdminPreference adminpreference)
        throws CreateException {
        setId(id);
        setAdminPreference(adminpreference);

        log.debug("Created admin preference " + id);

        return id;
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     */
    public void ejbPostCreate(String id, AdminPreference adminpreference) {
        // Do nothing. Required.
    }
}
