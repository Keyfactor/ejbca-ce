/*
 * AdminInformation.java
 *
 * Created on den 19 juli 2002, 11:53
 */
package se.anatom.ejbca.ra.authorization;

import java.security.cert.X509Certificate;


/**
 * A class used to send user information to the authorization tree. It can contain types of
 * information, a X509Certificate or a special user type when certificates cannot be retrieved.
 * Special usertype constants is specified in AdminEntity class.
 *
 * @version $Id: AdminInformation.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public class AdminInformation implements java.io.Serializable {
    // Public Methods

    /**
     * Creates a new instance of AdminInformation
     *
     * @param certificate DOCUMENT ME!
     */
    public AdminInformation(X509Certificate certificate) {
        this.certificate = certificate;
        this.specialuser = 0;
    }

    /**
     * Creates a new AdminInformation object.
     *
     * @param specialuser DOCUMENT ME!
     */
    public AdminInformation(int specialuser) {
        this.specialuser = specialuser;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean isSpecialUser() {
        return this.specialuser != 0;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public X509Certificate getX509Certificate() {
        return this.certificate;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getSpecialUser() {
        return this.specialuser;
    }

    // Private fields
    private X509Certificate certificate;
    private int specialuser = 0;
}
