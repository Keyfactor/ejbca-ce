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

import se.anatom.ejbca.ra.raadmin.EndEntityProfile;


/**
 * For docs, see EndEntityProfileDataBean
 *
 * @version $Id: EndEntityProfileDataLocal.java,v 1.4 2004-04-16 07:38:41 anatom Exp $
 */
public interface EndEntityProfileDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getProfileName();

    /**
     * DOCUMENT ME!
     *
     * @param profilename DOCUMENT ME!
     */
    public void setProfileName(String profilename);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public EndEntityProfile getProfile();

    /**
     * DOCUMENT ME!
     *
     * @param profile DOCUMENT ME!
     */
    public void setProfile(EndEntityProfile profile);
}
