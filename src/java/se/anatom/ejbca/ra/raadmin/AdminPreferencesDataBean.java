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
 * @version $Id: AdminPreferencesDataBean.java,v 1.10 2004-08-11 00:09:07 sbailliez Exp $
 *
 * @ejb.bean description="This enterprise bean entity represents a ra admins user preference."
 * display-name="AdminPreferencesDataEB"
 * name="AdminPreferencesData"
 * view-type="local"
 * type="CMP"
 * reentrant="false"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="AdminPreferencesDataBean"
 * primkey-field="id"
 *
 * @ejb.pk class="java.lang.String"
 * generate="false"
 *
 * @ejb.home
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="se.anatom.ejbca.ra.raadmin.AdminPreferencesDataLocalHome"
 *
 * @ejb.interface
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="se.anatom.ejbca.ra.raadmin.AdminPreferencesDataLocal"
 *
 */
public abstract class AdminPreferencesDataBean extends BaseEntityBean {
    private static final Logger log = Logger.getLogger(AdminPreferencesDataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getId();

    /**
     * @ejb.interface-method
     */
    public abstract void setId(String id);

    /**
     * @ejb.persistence
     */
    public abstract HashMap getData();
    public abstract void setData(HashMap data);

    /**
     * Method that returns the admin preference and updates it if nessesary.
     *
     * @return DOCUMENT ME!
     * @ejb.interface-method
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
     * @ejb.interface-method
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
     * @ejb.create-method
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
