package se.anatom.ejbca.ra.authorization;

/**
 * Primary key for AccessRules
 *
 * @version $Id: AccessRulesPK.java,v 1.5 2003-06-26 11:43:24 anatom Exp $
 */
public final class AccessRulesPK implements java.io.Serializable {
    public int pK;

    /**
     * Creates a new AccessRulesPK object.
     *
     * @param usergroupname name of user group
     * @param resource url of protected resource
     */
    public AccessRulesPK(java.lang.String usergroupname, java.lang.String resource) {
        this.pK = (((usergroupname == null) ? 0 : usergroupname.hashCode()) ^
            ((resource == null) ? 0 : resource.hashCode()));
    }

    /**
     * Creates a new AccessRulesPK object.
     */
    public AccessRulesPK() {
    }

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    public boolean equals(java.lang.Object otherOb) {
        if (!(otherOb instanceof se.anatom.ejbca.ra.authorization.AccessRulesPK)) {
            return false;
        }

        se.anatom.ejbca.ra.authorization.AccessRulesPK other = (se.anatom.ejbca.ra.authorization.AccessRulesPK) otherOb;

        return (pK == other.pK);
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.pK;
    }
}
