
package se.anatom.ejbca.authorization;

/**
 * @version $Id: AdminEntityPK.java,v 1.1 2003-09-04 14:26:37 herrvendil Exp $
 */

public final class AdminEntityPK implements java.io.Serializable {


    public int pK;


    public AdminEntityPK(java.lang.String admingroupname, int caid, int matchwith, int matchtype, java.lang.String matchvalue) {
        this.pK =
        ((admingroupname==null?0:admingroupname.hashCode())
        ^
        ((int) caid)
        ^
        ((int) matchwith)
        ^
        (matchvalue==null?0:matchvalue.hashCode())
        ^
        ((int) matchtype));
    }

    public AdminEntityPK() {
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object otherOb) {
        if (!(otherOb instanceof se.anatom.ejbca.authorization.AdminEntityPK)) {
            return false;
        }
        se.anatom.ejbca.authorization.AdminEntityPK other = (se.anatom.ejbca.authorization.AdminEntityPK) otherOb;
        return (this.pK == other.pK);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {

        return this.pK;

    }

}
