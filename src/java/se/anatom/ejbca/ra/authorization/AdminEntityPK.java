package se.anatom.ejbca.ra.authorization;

/**
 * DOCUMENT ME!
 *
 * @version $Id: AdminEntityPK.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public final class AdminEntityPK implements java.io.Serializable {
    public int pK;

    /**
     * Creates a new AdminEntityPK object.
     *
     * @param admingroupname DOCUMENT ME!
     * @param matchwith DOCUMENT ME!
     * @param matchtype DOCUMENT ME!
     * @param matchvalue DOCUMENT ME!
     */
    public AdminEntityPK(java.lang.String admingroupname, int matchwith, int matchtype,
        java.lang.String matchvalue) {
        this.pK = (((admingroupname == null) ? 0 : admingroupname.hashCode()) ^ ((int) matchwith) ^
            ((matchvalue == null) ? 0 : matchvalue.hashCode()) ^ ((int) matchtype));
    }

    /**
     * Creates a new AdminEntityPK object.
     */
    public AdminEntityPK() {
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object otherOb) {
        if (!(otherOb instanceof se.anatom.ejbca.ra.authorization.AdminEntityPK)) {
            return false;
        }

        se.anatom.ejbca.ra.authorization.AdminEntityPK other = (se.anatom.ejbca.ra.authorization.AdminEntityPK) otherOb;

        return (this.pK == other.pK);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.pK;
    }
}
