package se.anatom.ejbca.ra.authorization;

/**
 * For docs, see AccessRulesDataBean
 **/

public interface AccessRulesDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public String getDirectory();

    public AccessRule getAccessRule();
    public void setAccessRule(AccessRule accessrule);

}

