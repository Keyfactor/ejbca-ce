/*
 * UserInformation.java
 *
 * Created on den 19 juli 2002, 11:53
 */

package se.anatom.ejbca.ra.authorization;

import java.security.cert.X509Certificate;

/**
 * A class used to send user information to the authorization tree. It can contain types of information, a X509Certificate or a
 * special user type when certificates cannot be retrieved. Special usertype constants is specified in UserEntity class.
 *
 * @version $Id: UserInformation.java,v 1.2 2002-07-23 16:02:58 anatom Exp $
 */
public class UserInformation {

    // Public Methods
    /** Creates a new instance of UserInformation */
    public UserInformation(X509Certificate certificate){
      this.certificate=certificate;
      this.specialuser=0;
    }
    public UserInformation(int specialuser) {
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
