package se.anatom.ejbca;

/** Compount primary key for property entities.
 *
 * @version $Id: PropertyEntityPK.java,v 1.5 2004-01-25 09:37:10 herrvendil Exp $
 */

public final class PropertyEntityPK implements java.io.Serializable {

    public String id;
    public String property;

    public PropertyEntityPK(String id, String property) {
        this.id = id;
        this.property=property;
    }
    
    public String getId() {
        return id;
    }
    public String getProperty() {
        return property;
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object other) {
        if (other instanceof PropertyEntityPK) {
           return ( (id.equals(((PropertyEntityPK)other).id)) &&
               (property.equals(((PropertyEntityPK)other).property)) );
        }
        return false;
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.id.hashCode()^this.property.hashCode();
    }

}

