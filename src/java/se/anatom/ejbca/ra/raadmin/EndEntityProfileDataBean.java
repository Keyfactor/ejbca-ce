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
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * end entity profile in the ra. Information stored:
 * <pre>
 *  id (Primary key)
 * Profile name
 * Profile data
 * </pre>
 *
 * @version $Id: EndEntityProfileDataBean.java,v 1.7 2004-04-16 07:38:41 anatom Exp $
 */
public abstract class EndEntityProfileDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(EndEntityProfileDataBean.class);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     */
    public abstract void setId(Integer id);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getProfileName();

    /**
     * DOCUMENT ME!
     *
     * @param profilename DOCUMENT ME!
     */
    public abstract void setProfileName(String profilename);

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
     * Method that returns the end entity profiles and updates it if nessesary.
     *
     * @return DOCUMENT ME!
     */
    public EndEntityProfile getProfile() {
        EndEntityProfile returnval = new EndEntityProfile();
        returnval.loadData((Object) getData());

        return returnval;
    }

    /**
     * Method that saves the admin preference to database.
     *
     * @param profile DOCUMENT ME!
     */
    public void setProfile(EndEntityProfile profile) {
        setData((HashMap) profile.saveData());
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
