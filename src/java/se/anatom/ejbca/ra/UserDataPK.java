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
 
package se.anatom.ejbca.ra;

import se.anatom.ejbca.util.StringTools;


/**
 * The primary key of the User is the username fingerprint which should be unique.
 *
 * @version $Id: UserDataPK.java,v 1.7 2004-04-16 07:38:56 anatom Exp $
 */
public class UserDataPK implements java.io.Serializable {
    public String username;

    /**
     * Creates a new UserDataPK object.
     *
     * @param username DOCUMENT ME!
     */
    public UserDataPK(String username) {
        this.username = StringTools.strip(username);
    }

    /**
     * Creates a new UserDataPK object.
     */
    public UserDataPK() {
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int hashCode() {
        return username.hashCode();
    }

    /**
     * DOCUMENT ME!
     *
     * @param obj DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean equals(Object obj) {
        return ((UserDataPK) obj).username.equals(username);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String toString() {
        return username.toString();
    }
}
