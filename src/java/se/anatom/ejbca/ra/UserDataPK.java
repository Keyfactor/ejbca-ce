package se.anatom.ejbca.ra;

import se.anatom.ejbca.util.StringTools;

/**
 * The primary key of the User is the username fingerprint which should be unique.
 *
 * @version $Id: UserDataPK.java,v 1.5 2002-07-05 23:43:18 herrvendil Exp $
 **/

public class UserDataPK implements java.io.Serializable {
    
    public String username;

    public UserDataPK(String username) {
        this.username = StringTools.strip(username);
    }

    public UserDataPK() {
    }

    public int hashCode(){
        return username.hashCode();
    }

    public boolean equals(Object obj){
            return ((UserDataPK)obj).username.equals(username);
    }

    public String toString(){
       return username.toString();
    }

}

