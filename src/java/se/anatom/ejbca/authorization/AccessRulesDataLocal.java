package se.anatom.ejbca.authorization;

/**
 * For docs, see AccessRulesDataBean
 **/

public interface AccessRulesDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public String getAccessRule();

    public AccessRule getAccessRuleObject();
    public void setAccessRuleObject(AccessRule accessrule);

}

