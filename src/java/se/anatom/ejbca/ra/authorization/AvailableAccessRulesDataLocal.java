package se.anatom.ejbca.ra.authorization;

/**
 * For docs, see AvailableAccessRulesDataBean
 */
public interface AvailableAccessRulesDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public String getName();

    /**
     * sets name of access rule
     *
     * @param name name
     */
    public void setName(String name);
}
