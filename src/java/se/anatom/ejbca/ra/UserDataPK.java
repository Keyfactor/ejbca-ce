package se.anatom.ejbca.ra;

import se.anatom.ejbca.util.StringTools;


/**
 * The primary key of the User is the username fingerprint which should be unique.
 *
 * @version $Id: UserDataPK.java,v 1.6 2003-06-26 11:43:24 anatom Exp $
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
