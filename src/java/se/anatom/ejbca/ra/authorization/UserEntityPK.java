
package se.anatom.ejbca.ra.authorization;

/**
 * @version $Id: UserEntityPK.java,v 1.4 2002-07-26 11:11:51 anatom Exp $
 */

public final class UserEntityPK implements java.io.Serializable {


    public int pK;


    public UserEntityPK(java.lang.String usergroupname, int matchwith, int matchtype, java.lang.String matchvalue) {
        this.pK =
        ((usergroupname==null?0:usergroupname.hashCode())
        ^
        ((int) matchwith)
        ^
        (matchvalue==null?0:matchvalue.hashCode())
        ^
        ((int) matchtype));
    }

    public UserEntityPK() {
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object otherOb) {
        if (!(otherOb instanceof se.anatom.ejbca.ra.authorization.UserEntityPK)) {
            return false;
        }
        se.anatom.ejbca.ra.authorization.UserEntityPK other = (se.anatom.ejbca.ra.authorization.UserEntityPK) otherOb;
        return (this.pK == other.pK);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {

        return this.pK;

    }

}
