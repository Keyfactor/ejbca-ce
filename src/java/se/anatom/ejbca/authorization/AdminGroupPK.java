
package se.anatom.ejbca.authorization;

/**
 * @version $Id: AdminGroupPK.java,v 1.1 2003-09-04 14:26:37 herrvendil Exp $
 */

public final class AdminGroupPK implements java.io.Serializable {


    public int pK;


    public AdminGroupPK(java.lang.String admingroupname, int caid) {
        this.pK =
        ((admingroupname==null?0:admingroupname.hashCode())
        ^
        ((int) caid));        
      
    }

    public AdminGroupPK() {
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object otherOb) {
        if (!(otherOb instanceof se.anatom.ejbca.authorization.AdminGroupPK)) {
            return false;
        }
        se.anatom.ejbca.authorization.AdminGroupPK other = (se.anatom.ejbca.authorization.AdminGroupPK) otherOb;
        return (this.pK == other.pK);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.pK;
    }

}
