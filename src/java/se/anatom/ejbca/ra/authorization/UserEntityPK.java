
package se.anatom.ejbca.ra.authorization;

/**
 * @version $Id: UserEntityPK.java,v 1.2 2002-07-23 16:02:58 anatom Exp $
 */

public final class UserEntityPK implements java.io.Serializable {

    public java.lang.String usergroupname;
    public int matchwith;
    public int matchtype;
    public java.lang.String matchvalue;

    public UserEntityPK(java.lang.String usergroupname, int matchwith, int matchtype, java.lang.String matchvalue){
      this.usergroupname=usergroupname;
      this.matchwith=matchwith;
      this.matchtype=matchtype;
      this.matchvalue=matchvalue;
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
        return (
        (usergroupname==null?other.usergroupname==null:usergroupname.equals(other.usergroupname))
        &&
        (matchwith == other.matchwith)
        &&
        (matchvalue==null?other.matchvalue==null:matchvalue.equals(other.matchvalue))
        &&
        (matchtype == other.matchtype)

        );
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return (
        (usergroupname==null?0:usergroupname.hashCode())
        ^
        ((int) matchwith)
        ^
        (matchvalue==null?0:matchvalue.hashCode())
        ^
        ((int) matchtype)

        );
    }

}
