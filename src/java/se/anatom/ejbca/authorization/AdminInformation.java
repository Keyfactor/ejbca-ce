/*
 * AdminInformation.java
 *
 * Created on den 19 juli 2002, 11:53
 */

package se.anatom.ejbca.authorization;

import java.security.cert.X509Certificate;

/**
 * A class used to send user information to the authorization tree. It can contain types of information, a X509Certificate or a
 * special user type when certificates cannot be retrieved. Special usertype constants is specified in AdminEntity class.
 *
 * @version $Id: AdminInformation.java,v 1.1 2003-09-04 14:26:37 herrvendil Exp $
 */
public class AdminInformation implements java.io.Serializable {

    // Public Methods
    /** Creates a new instance of AdminInformation */
    public AdminInformation(X509Certificate certificate){
      this.certificate=certificate;
      this.specialuser=0;
    }
    public AdminInformation(int specialuser) {
      this.specialuser=specialuser;
    }

    public boolean isSpecialUser() {
      return this.specialuser!=0;
    }

    public X509Certificate getX509Certificate() {
      return this.certificate;
    }

    public int getSpecialUser() {
      return this.specialuser;
    }

    // Private fields
    private X509Certificate certificate;
    private int specialuser = 0;
}
