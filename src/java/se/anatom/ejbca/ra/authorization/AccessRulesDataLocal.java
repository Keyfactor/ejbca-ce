package se.anatom.ejbca.ra.authorization;

/**
 * For docs, see AccessRulesDataBean
 */
public interface AccessRulesDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public String getResource();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public AccessRule getAccessRule();

    /**
     * DOCUMENT ME!
     *
     * @param accessrule DOCUMENT ME!
     */
    public void setAccessRule(AccessRule accessrule);
}
