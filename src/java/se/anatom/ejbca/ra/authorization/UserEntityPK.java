
package se.anatom.ejbca.ra.authorization;

/**
 * @version $Id: UserEntityPK.java,v 1.3 2002-07-26 09:29:24 herrvendil Exp $
 */

public final class UserEntityPK implements java.io.Serializable {

 
    public int fingerprint;
    

    public UserEntityPK(java.lang.String usergroupname, int matchwith, int matchtype, java.lang.String matchvalue){
        this.fingerprint =
        ((usergroupname==null?0:usergroupname.hashCode())
        ^
        ((int) matchwith)
        ^
        (matchvalue==null?0:matchvalue.hashCode())
        ^
        ((int) matchtype));
    }


    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object otherOb) {

        if (this == otherOb) {
            return true;
        }
        if (!(otherOb instanceof se.anatom.ejbca.ra.authorization.UserEntityPK)) {
            return false;
        }
        se.anatom.ejbca.ra.authorization.UserEntityPK other = (se.anatom.ejbca.ra.authorization.UserEntityPK) otherOb;
        return (this.fingerprint == other.fingerprint);

    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {

        return this.fingerprint;

    }

}
