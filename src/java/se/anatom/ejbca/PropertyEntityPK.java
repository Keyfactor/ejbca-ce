package se.anatom.ejbca;

/**
 * @version $Id: PropertyEntityPK.java,v 1.1 2004-01-08 14:31:26 herrvendil Exp $
 */

public final class PropertyEntityPK implements java.io.Serializable {


    public int pK;


    public PropertyEntityPK(int id, String property) {
        this.pK =
        ((property==null?0:property.hashCode())
        ^
        ((int) id));
    }



    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object otherOb) {
        if (!(otherOb instanceof se.anatom.ejbca.PropertyEntityPK)) {
            return false;
        }
        se.anatom.ejbca.PropertyEntityPK other = (se.anatom.ejbca.PropertyEntityPK) otherOb;
        return (this.pK == other.pK);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {

        return this.pK;

    }

}
