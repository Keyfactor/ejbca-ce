package se.anatom.ejbca;

/** Compount primary key for property entities.
 *
 * @version $Id: PropertyEntityPK.java,v 1.3 2004-01-09 11:20:56 anatom Exp $
 */

public final class PropertyEntityPK implements java.io.Serializable {

    public int id;
    public String property;

    public PropertyEntityPK(int id, String property) {
        this.id = id;
        this.property=property;
    }
    
    public int getId() {
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
           return ( (id == ((PropertyEntityPK)other).id) &&
               (property.equals(((PropertyEntityPK)other).property)) );
        }
        return false;
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.id;
    }

}

