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
 
package org.ejbca.core.ejb.ra.raadmin;

import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;




/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * end entity profile in the ra. Information stored:
 * <pre>
 *  id (Primary key)
 * Profile name
 * Profile data
 * </pre>
 *
 * @version $Id$
 *
 * @ejb.bean description="This enterprise bean entity represents a profile"
 * display-name="EndEntityProfileDataEB"
 * name="EndEntityProfileData"
 * jndi-name="EndEntityProfileData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="EndEntityProfileDataBean"
 * primkey-field="id"
 *
 * @ejb.pk class="java.lang.Integer"
 * generate="false"
 *
 * @ejb.persistence table-name = "EndEntityProfileData"
 *
 * @ejb.transaction type="Required"
 * 
 * @ejb.home
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.ejbca.core.ejb.ra.raadmin.EndEntityProfileDataLocalHome"
 *
 * @ejb.interface
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.ejbca.core.ejb.ra.raadmin.EndEntityProfileDataLocal"
 *
 * @ejb.finder
 *   description="findByProfileName"
 *   signature="org.ejbca.core.ejb.ra.raadmin.EndEntityProfileDataLocal findByProfileName(java.lang.String name)"
 *   query="SELECT OBJECT(a) from EndEntityProfileDataBean a WHERE a.profileName=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="java.util.Collection findAll()"
 *   query="SELECT OBJECT(a) from EndEntityProfileDataBean a"
 *
 * @jboss.method-attributes
 *   pattern = "get*"
 *   read-only = "true"
 *
 */
public abstract class EndEntityProfileDataBean extends BaseEntityBean implements java.io.Serializable {
    private static final Logger log = Logger.getLogger(EndEntityProfileDataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="id"
     * @ejb.interface-method
     */
    public abstract Integer getId();

    /**
     */
    public abstract void setId(Integer id);

    /**
     * @ejb.persistence column-name="profileName"
     * @ejb.interface-method
     */
    public abstract String getProfileName();

    /**
     * @ejb.interface-method
     */
    public abstract void setProfileName(String profilename);

    /**
     * @ejb.persistence column-name="data"
     * @weblogic.ora.columntyp@
     */
    public abstract HashMap getData();

    /**
     */
    public abstract void setData(HashMap data);

    /**
     * Method that returns the end entity profiles and updates it if nessesary.
     *
     * @return DOCUMENT ME!
     * @ejb.interface-method
     */
    public EndEntityProfile getProfile() {
    	return readAndUpgradeProfileInternal();
    }

    /**
     * Method that saves the admin preference to database.
     *
     * @param profile DOCUMENT ME!
     * @ejb.interface-method
     */
    public void setProfile(EndEntityProfile profile) {
        setData((HashMap) profile.saveData());
    }

    /** 
     * Method that upgrades a EndEntity Profile, if needed.
     * @ejb.interface-method
     */
    public void upgradeProfile() {
    	readAndUpgradeProfileInternal();
    }

    /** We have an internal method for this read operation with a side-effect. 
     * This is because getCertificateProfile() is a read-only method, so the possible side-effect of upgrade will not happen,
     * and therefore this internal method can be called from another non-read-only method, upgradeProfile().
     * @return CertificateProfile
     */
    private EndEntityProfile readAndUpgradeProfileInternal() {
        EndEntityProfile returnval = new EndEntityProfile();
        HashMap data = getData();
        // If EndEntityProfile-data is upgraded we want to save the new data, so we must get the old version before loading the data 
        // and perhaps upgrading
        float oldversion = ((Float) data.get(UpgradeableDataHashMap.VERSION)).floatValue();
        // Load the profile data, this will potentially upgrade the CertificateProfile
        returnval.loadData(data);
        if (Float.compare(oldversion, returnval.getVersion()) != 0) {
        	// Save new data versions differ
        	setProfile(returnval);
        }
        return returnval;
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of a end entity profile.
     *
     * @param profilename DOCUMENT ME!
     * @param profilename
     * @param profile is the EndEntityProfile.
     *
     * @return null
     * @ejb.create-method
     */
    public Integer ejbCreate(Integer id, String profilename, EndEntityProfile profile)
        throws CreateException {
        setId(id);
        setProfileName(profilename);
        setProfile(profile);
        log.debug("Created profile " + profilename);

        return id;
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param profilename DOCUMENT ME!
     * @param profile DOCUMENT ME!
     */
    public void ejbPostCreate(Integer id, String profilename, EndEntityProfile profile) {
        // Do nothing. Required.
    }
}
